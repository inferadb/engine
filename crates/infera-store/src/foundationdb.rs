//! FoundationDB storage backend
//!
//! Provides a production-ready storage backend using FoundationDB.
//! FoundationDB offers:
//! - ACID transactions
//! - Multi-version concurrency control (MVCC)
//! - Horizontal scalability
//! - High availability

use async_trait::async_trait;
use foundationdb::relationship::{Subspace, pack, unpack};
use foundationdb::{Database, FdbError, TransactOption};
use serde_json;
use std::sync::Arc;
use tracing::{debug, error, warn};

use crate::{Relationship, RelationshipKey, RelationshipStore, Result, Revision, StoreError};
use infera_types::{ChangeEvent, DeleteFilter};

/// FoundationDB storage backend
pub struct FoundationDBBackend {
    db: Arc<Database>,
    // Subspaces for organizing data
    relationships_subspace: Subspace,
    revision_subspace: Subspace,
    index_subspace: Subspace,
    changelog_subspace: Subspace,
}

impl FoundationDBBackend {
    /// Create a new FoundationDB backend
    pub async fn new() -> Result<Self> {
        Self::with_cluster_file(None).await
    }

    /// Create a new FoundationDB backend with a specific cluster file
    pub async fn with_cluster_file(cluster_file: Option<&str>) -> Result<Self> {
        // Initialize FDB API
        let network = foundationdb::boot()
            .map_err(|e| StoreError::Database(format!("Failed to initialize FDB: {}", e)))?;

        // Create database handle
        let db = if let Some(path) = cluster_file {
            Database::from_path(path)
                .map_err(|e| StoreError::Database(format!("Failed to open cluster file: {}", e)))?
        } else {
            Database::default().map_err(|e| {
                StoreError::Database(format!("Failed to open default cluster: {}", e))
            })?
        };

        // Create subspaces for different data types
        let relationships_subspace = Subspace::from_bytes(b"relationships");
        let revision_subspace = Subspace::from_bytes(b"revisions");
        let index_subspace = Subspace::from_bytes(b"indexes");
        let changelog_subspace = Subspace::from_bytes(b"changelog");

        debug!("FoundationDB backend initialized");

        Ok(Self {
            db: Arc::new(db),
            relationships_subspace,
            revision_subspace,
            index_subspace,
            changelog_subspace,
        })
    }

    /// Get the current global revision
    async fn get_current_revision(&self) -> Result<Revision> {
        let db = Arc::clone(&self.db);
        let revision_key = self.revision_subspace.pack(&("current",));

        let result = db
            .run(move |trx, _maybe_committed| async move {
                match trx.get(&revision_key, false).await? {
                    Some(bytes) => {
                        let rev: u64 = serde_json::from_slice(&bytes).map_err(|e| {
                            FdbError::from(format!("Failed to deserialize revision: {}", e))
                        })?;
                        Ok(Revision(rev))
                    }
                    None => Ok(Revision::zero()),
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to get revision: {}", e)))?;

        Ok(result)
    }

    /// Increment and return the next revision
    async fn increment_revision(&self) -> Result<Revision> {
        let db = Arc::clone(&self.db);
        let revision_key = self.revision_subspace.pack(&("current",));

        let result = db
            .run(move |trx, _maybe_committed| async move {
                let current = match trx.get(&revision_key, false).await? {
                    Some(bytes) => {
                        let rev: u64 = serde_json::from_slice(&bytes)
                            .map_err(|e| FdbError::from(format!("Failed to deserialize: {}", e)))?;
                        rev
                    }
                    None => 0,
                };

                let next = current + 1;
                let bytes = serde_json::to_vec(&next)
                    .map_err(|e| FdbError::from(format!("Failed to serialize: {}", e)))?;

                trx.set(&revision_key, &bytes);
                Ok(Revision(next))
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to increment revision: {}", e)))?;

        Ok(result)
    }

    /// Create a key for a relationship with revision
    fn relationship_key(&self, relationship: &Tuple, revision: Revision) -> Vec<u8> {
        self.relationships_subspace.pack(&(
            &relationship.resource,
            &relationship.relation,
            &relationship.subject,
            revision.0,
        ))
    }

    /// Create an index key for object/relation lookups
    fn index_key_object(
        &self,
        resource: &str,
        relation: &str,
        subject: &str,
        revision: Revision,
    ) -> Vec<u8> {
        self.index_subspace
            .pack(&("obj", object, relation, user, revision.0))
    }

    /// Create an index key for reverse lookups (user/relation)
    fn index_key_user(
        &self,
        subject: &str,
        relation: &str,
        resource: &str,
        revision: Revision,
    ) -> Vec<u8> {
        self.index_subspace
            .pack(&("user", user, relation, object, revision.0))
    }

    /// Parse a relationship from a key
    fn parse_relationship_from_key(&self, key: &[u8]) -> Result<Relationship> {
        let unpacked: (String, String, String, u64) =
            unpack(&key[self.relationships_subspace.bytes().len()..]).map_err(|e| {
                StoreError::Serialization(serde_json::Error::custom(format!(
                    "Failed to unpack relationship key: {}",
                    e
                )))
            })?;

        Ok(Relationship {
            resource: unpacked.0,
            relation: unpacked.1,
            subject: unpacked.2,
        })
    }
}

#[async_trait]
impl RelationshipStore for FoundationDBBackend {
    async fn read(&self, key: &RelationshipKey, revision: Revision) -> Result<Vec<Relationship>> {
        let db = Arc::clone(&self.db);
        let object = key.resource.clone();
        let relation = key.relation.clone();
        let user_filter = key.subject.clone();

        // Create range for this object+relation at or before the revision
        let start_key = self.index_subspace.pack(&("obj", &object, &relation));
        let end_key = self.index_subspace.pack(&(
            "obj",
            &object,
            &relation,
            "\u{10FFFF}", // Max valid Unicode scalar value for range upper bound
        ));

        let relationships_subspace = self.relationships_subspace.clone();

        let result = db
            .run(move |trx, _maybe_committed| async move {
                let range = trx
                    .get_range(
                        &foundationdb::RangeOption {
                            begin: foundationdb::KeySelector::first_greater_or_equal(&start_key),
                            end: foundationdb::KeySelector::first_greater_or_equal(&end_key),
                            limit: None,
                            reverse: false,
                            mode: foundationdb::StreamingMode::WantAll,
                        },
                        1,
                        false,
                    )
                    .await?;

                let mut relationships = Vec::new();
                let mut seen = std::collections::HashSet::new();

                for kv in range.iter() {
                    let unpacked: (String, String, String, String, u64) =
                        unpack(&kv.key()[relationships_subspace.bytes().len()..]).map_err(|e| {
                            FdbError::from(format!("Failed to unpack index: {}", e))
                        })?;

                    let (_prefix, _obj, _rel, user, rev) = unpacked;

                    // Only include relationships at or before requested revision
                    if rev > revision.0 {
                        continue;
                    }

                    // Apply user filter if specified
                    if let Some(ref filter_user) = user_filter {
                        if &user != filter_user {
                            continue;
                        }
                    }

                    // Deduplicate - only keep latest version of each relationship
                    let relationship_id = format!("{}:{}:{}", object, relation, user);
                    if !seen.contains(&relationship_id) {
                        seen.insert(relationship_id);

                        // Check if this relationship is still active (not deleted)
                        let relationship_key =
                            relationships_subspace.pack(&(&object, &relation, &user, rev));
                        if let Some(value) = trx.get(&relationship_key, false).await? {
                            if &value == b"active" {
                                relationships.push(Relationship {
                                    resource: object.clone(),
                                    relation: relation.clone(),
                                    subject: user.clone(),
                                });
                            }
                        }
                    }
                }

                Ok(relationships)
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to read: {}", e)))?;

        debug!(
            "Read {} relationships for {}:{}",
            result.len(),
            key.resource,
            key.relation
        );
        Ok(result)
    }

    async fn write(&self, relationships: Vec<Relationship>) -> Result<Revision> {
        if relationships.is_empty() {
            return self.get_current_revision().await;
        }

        let db = Arc::clone(&self.db);
        let relationships_subspace = self.relationships_subspace.clone();
        let index_subspace = self.index_subspace.clone();
        let revision_key = self.revision_subspace.pack(&("current",));

        let result = db
            .run(move |trx, _maybe_committed| async move {
                // Get and increment revision
                let current = match trx.get(&revision_key, false).await? {
                    Some(bytes) => {
                        let rev: u64 = serde_json::from_slice(&bytes)
                            .map_err(|e| FdbError::from(format!("Failed to deserialize: {}", e)))?;
                        rev
                    }
                    None => 0,
                };

                let next_rev = current + 1;
                let rev_bytes = serde_json::to_vec(&next_rev)
                    .map_err(|e| FdbError::from(format!("Failed to serialize: {}", e)))?;
                trx.set(&revision_key, &rev_bytes);

                let revision = Revision(next_rev);

                // Write each relationship
                for relationship in &relationships {
                    // Write relationship data
                    let relationship_key = relationships_subspace.pack(&(
                        &relationship.resource,
                        &relationship.relation,
                        &relationship.subject,
                        revision.0,
                    ));
                    trx.set(&relationship_key, b"active");

                    // Write index for object lookups
                    let obj_index = index_subspace.pack(&(
                        "obj",
                        &relationship.resource,
                        &relationship.relation,
                        &relationship.subject,
                        revision.0,
                    ));
                    trx.set(&obj_index, b"");

                    // Write index for reverse lookups
                    let subject_index = index_subspace.pack(&(
                        "user",
                        &relationship.subject,
                        &relationship.relation,
                        &relationship.resource,
                        revision.0,
                    ));
                    trx.set(&subject_index, b"");
                }

                Ok(revision)
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to write: {}", e)))?;

        debug!(
            "Wrote {} relationships at revision {:?}",
            relationships.len(),
            result
        );
        Ok(result)
    }

    async fn get_revision(&self) -> Result<Revision> {
        self.get_current_revision().await
    }

    async fn delete(&self, key: &RelationshipKey) -> Result<Revision> {
        let db = Arc::clone(&self.db);
        let object = key.resource.clone();
        let relation = key.relation.clone();
        let user_filter = key.subject.clone();
        let relationships_subspace = self.relationships_subspace.clone();
        let revision_key = self.revision_subspace.pack(&("current",));

        let result = db
            .run(move |trx, _maybe_committed| async move {
                // Get and increment revision
                let current = match trx.get(&revision_key, false).await? {
                    Some(bytes) => {
                        let rev: u64 = serde_json::from_slice(&bytes)
                            .map_err(|e| FdbError::from(format!("Failed to deserialize: {}", e)))?;
                        rev
                    }
                    None => 0,
                };

                let next_rev = current + 1;
                let rev_bytes = serde_json::to_vec(&next_rev)
                    .map_err(|e| FdbError::from(format!("Failed to serialize: {}", e)))?;
                trx.set(&revision_key, &rev_bytes);

                let revision = Revision(next_rev);

                // Mark matching relationships as deleted
                if let Some(user) = user_filter {
                    // Delete specific relationship
                    let relationship_key =
                        relationships_subspace.pack(&(&object, &relation, &user, revision.0));
                    trx.set(&relationship_key, b"deleted");
                } else {
                    // Delete all relationships matching object+relation
                    // We write a deletion marker for each unique user we find
                    let start_key = relationships_subspace.pack(&(&object, &relation));
                    let end_key = relationships_subspace.pack(&(&object, &relation, "\u{10FFFF}"));

                    let range = trx
                        .get_range(
                            &foundationdb::RangeOption {
                                begin: foundationdb::KeySelector::first_greater_or_equal(
                                    &start_key,
                                ),
                                end: foundationdb::KeySelector::first_greater_or_equal(&end_key),
                                limit: None,
                                reverse: false,
                                mode: foundationdb::StreamingMode::WantAll,
                            },
                            1,
                            false,
                        )
                        .await?;

                    let mut deleted_users = std::collections::HashSet::new();
                    for kv in range.iter() {
                        let unpacked: (String, String, String, u64) =
                            unpack(&kv.key()[relationships_subspace.bytes().len()..])
                                .map_err(|e| FdbError::from(format!("Failed to unpack: {}", e)))?;

                        let (_obj, _rel, user, _rev) = unpacked;
                        if !deleted_users.contains(&user) {
                            deleted_users.insert(user.clone());
                            let del_key = relationships_subspace
                                .pack(&(&object, &relation, &user, revision.0));
                            trx.set(&del_key, b"deleted");
                        }
                    }
                }

                Ok(revision)
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to delete: {}", e)))?;

        debug!(
            "Deleted relationships matching {}:{} at revision {:?}",
            key.resource, key.relation, result
        );
        Ok(result)
    }

    async fn delete_by_filter(
        &self,
        filter: &DeleteFilter,
        limit: Option<usize>,
    ) -> Result<(Revision, usize)> {
        // Validate filter is not empty
        if filter.is_empty() {
            return Err(StoreError::Internal(
                "Filter must have at least one field set".to_string(),
            ));
        }

        let db = Arc::clone(&self.db);
        let filter = filter.clone();
        let relationships_subspace = self.relationships_subspace.clone();
        let revision_key = self.revision_subspace.pack(&("current",));

        let result = db
            .run(move |trx, _maybe_committed| async move {
                // Get and increment revision
                let current = match trx.get(&revision_key, false).await? {
                    Some(bytes) => {
                        let rev: u64 = serde_json::from_slice(&bytes)
                            .map_err(|e| FdbError::from(format!("Failed to deserialize: {}", e)))?;
                        rev
                    }
                    None => 0,
                };

                let next_rev = current + 1;
                let rev_bytes = serde_json::to_vec(&next_rev)
                    .map_err(|e| FdbError::from(format!("Failed to serialize: {}", e)))?;
                trx.set(&revision_key, &rev_bytes);

                let revision = Revision(next_rev);

                // Scan all relationships and match against filter
                // This is a full scan - could be optimized with better indexing
                let start_key = relationships_subspace.pack(&());
                let end_key = relationships_subspace.pack(&("\u{10FFFF}",));

                let range = trx
                    .get_range(
                        &foundationdb::RangeOption {
                            begin: foundationdb::KeySelector::first_greater_or_equal(&start_key),
                            end: foundationdb::KeySelector::first_greater_or_equal(&end_key),
                            limit: None,
                            reverse: false,
                            mode: foundationdb::StreamingMode::WantAll,
                        },
                        1,
                        false,
                    )
                    .await?;

                let mut deleted_count = 0;
                let mut deleted_keys = std::collections::HashSet::new();

                for kv in range.iter() {
                    // Skip if already at limit
                    if let Some(lim) = limit {
                        if lim > 0 && deleted_count >= lim {
                            break;
                        }
                    }

                    let unpacked: (String, String, String, u64) =
                        unpack(&kv.key()[relationships_subspace.bytes().len()..])
                            .map_err(|e| FdbError::from(format!("Failed to unpack: {}", e)))?;

                    let (resource, relation, subject, _rev) = unpacked;

                    // Skip if already marked as deleted
                    if kv.value() == b"deleted" {
                        continue;
                    }

                    // Check filter conditions
                    let matches = match (&filter.resource, &filter.relation, &filter.subject) {
                        // All three specified (exact match)
                        (Some(res), Some(rel_name), Some(sub)) => {
                            resource == *res && relation == *rel_name && subject == *sub
                        }
                        // Resource + Relation
                        (Some(res), Some(rel_name), None) => {
                            resource == *res && relation == *rel_name
                        }
                        // Resource + Subject
                        (Some(res), None, Some(sub)) => resource == *res && subject == *sub,
                        // Relation + Subject
                        (None, Some(rel_name), Some(sub)) => {
                            relation == *rel_name && subject == *sub
                        }
                        // Resource only
                        (Some(res), None, None) => resource == *res,
                        // Relation only
                        (None, Some(rel_name), None) => relation == *rel_name,
                        // Subject only (user offboarding)
                        (None, None, Some(sub)) => subject == *sub,
                        // None (should be caught by filter.is_empty())
                        (None, None, None) => false,
                    };

                    if matches {
                        // Create unique key for this relationship (without revision)
                        let unique_key = (&resource, &relation, &subject);
                        if !deleted_keys.contains(&unique_key) {
                            deleted_keys.insert(unique_key);

                            // Write deletion marker at new revision
                            let del_key = relationships_subspace
                                .pack(&(&resource, &relation, &subject, revision.0));
                            trx.set(&del_key, b"deleted");
                            deleted_count += 1;
                        }
                    }
                }

                Ok((revision, deleted_count))
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to delete by filter: {}", e)))?;

        debug!(
            "Deleted {} relationships matching filter at revision {:?}",
            result.1, result.0
        );
        Ok(result)
    }

    async fn list_resources_by_type(
        &self,
        object_type: &str,
        revision: Revision,
    ) -> Result<Vec<String>> {
        let db = Arc::clone(&self.db);
        let object_type = object_type.to_string();
        let index_subspace = self.index_subspace.clone();
        let relationships_subspace = self.relationships_subspace.clone();

        // Build the type prefix (e.g., "document:")
        let type_prefix = format!("{}:", object_type);
        let type_end = format!("{};\u{0}", object_type); // Next string after "type:"

        let result = db
            .run(move |trx, _maybe_committed| async move {
                // Query range of all objects with this type prefix
                let start_key = index_subspace.pack(&("obj", type_prefix.as_str()));
                let end_key = index_subspace.pack(&("obj", type_end.as_str()));

                let range = trx
                    .get_range(
                        &foundationdb::RangeOption {
                            begin: foundationdb::KeySelector::first_greater_or_equal(&start_key),
                            end: foundationdb::KeySelector::first_greater_or_equal(&end_key),
                            limit: None,
                            reverse: false,
                            mode: foundationdb::StreamingMode::WantAll,
                        },
                        1,
                        false,
                    )
                    .await?;

                let mut objects = std::collections::HashSet::new();

                for kv in range.iter() {
                    // Unpack: ("obj", object, relation, user, rev)
                    let unpacked: (String, String, String, String, u64) =
                        unpack(&kv.key()[index_subspace.bytes().len()..]).map_err(|e| {
                            FdbError::from(format!("Failed to unpack index: {}", e))
                        })?;

                    let (_prefix, object, relation, user, rev) = unpacked;

                    // Only include relationships at or before requested revision
                    if rev > revision.0 {
                        continue;
                    }

                    // Check if this relationship is still active at the requested revision
                    let relationship_key =
                        relationships_subspace.pack(&(&object, &relation, &user, rev));
                    if let Some(value) = trx.get(&relationship_key, false).await? {
                        if &value == b"active" {
                            objects.insert(object);
                        }
                    }
                }

                // Convert to sorted vector for deterministic output
                let mut result: Vec<String> = objects.into_iter().collect();
                result.sort();

                Ok(result)
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to list objects by type: {}", e)))?;

        debug!("Listed {} objects of type '{}'", result.len(), object_type);
        Ok(result)
    }

    async fn list_relationships(
        &self,
        resource: Option<&str>,
        relation: Option<&str>,
        subject: Option<&str>,
        revision: Revision,
    ) -> Result<Vec<Relationship>> {
        let db = Arc::clone(&self.db);
        // Map API parameter names to internal relationship field names
        let object_filter = resource.map(|s| s.to_string());
        let relation_filter = relation.map(|s| s.to_string());
        let user_filter = subject.map(|s| s.to_string());
        let index_subspace = self.index_subspace.clone();
        let relationships_subspace = self.relationships_subspace.clone();

        let result = db
            .run(move |trx, _maybe_committed| async move {
                let mut relationships = Vec::new();
                let mut seen = std::collections::HashSet::new();

                // Determine the best index to use based on provided filters
                match (&object_filter, &relation_filter, &user_filter) {
                    // Use object index when we have object filter
                    (Some(obj), Some(rel), _) | (Some(obj), None, _) => {
                        let start_key = if let Some(rel) = &relation_filter {
                            index_subspace.pack(&("obj", obj.as_str(), rel.as_str()))
                        } else {
                            index_subspace.pack(&("obj", obj.as_str()))
                        };
                        let end_key = if let Some(rel) = &relation_filter {
                            index_subspace.pack(&("obj", obj.as_str(), rel.as_str(), "\u{10FFFF}"))
                        } else {
                            index_subspace.pack(&("obj", obj.as_str(), "\u{10FFFF}"))
                        };

                        let range = trx
                            .get_range(
                                &foundationdb::RangeOption {
                                    begin: foundationdb::KeySelector::first_greater_or_equal(
                                        &start_key,
                                    ),
                                    end: foundationdb::KeySelector::first_greater_or_equal(
                                        &end_key,
                                    ),
                                    limit: None,
                                    reverse: false,
                                    mode: foundationdb::StreamingMode::WantAll,
                                },
                                1,
                                false,
                            )
                            .await?;

                        for kv in range.iter() {
                            let unpacked: (String, String, String, String, u64) =
                                unpack(&kv.key()[index_subspace.bytes().len()..]).map_err(|e| {
                                    FdbError::from(format!("Failed to unpack: {}", e))
                                })?;

                            let (_prefix, object, relation, user, rev) = unpacked;

                            // Filter by revision
                            if rev > revision.0 {
                                continue;
                            }

                            // Apply user filter if needed
                            if let Some(ref filter_user) = user_filter {
                                if &user != filter_user {
                                    continue;
                                }
                            }

                            // Deduplicate
                            let relationship_id = format!("{}:{}:{}", object, relation, user);
                            if seen.contains(&relationship_id) {
                                continue;
                            }
                            seen.insert(relationship_id);

                            // Check if active
                            let relationship_key =
                                relationships_subspace.pack(&(&object, &relation, &user, rev));
                            if let Some(value) = trx.get(&relationship_key, false).await? {
                                if &value == b"active" {
                                    relationships.push(Relationship {
                                        object,
                                        relation,
                                        user,
                                    });
                                }
                            }
                        }
                    }
                    // Use user index when we have user filter (but no object filter)
                    (None, Some(rel), Some(usr)) | (None, None, Some(usr)) => {
                        let start_key = if let Some(rel) = &relation_filter {
                            index_subspace.pack(&("user", usr.as_str(), rel.as_str()))
                        } else {
                            index_subspace.pack(&("user", usr.as_str()))
                        };
                        let end_key = if let Some(rel) = &relation_filter {
                            index_subspace.pack(&("user", usr.as_str(), rel.as_str(), "\u{10FFFF}"))
                        } else {
                            index_subspace.pack(&("user", usr.as_str(), "\u{10FFFF}"))
                        };

                        let range = trx
                            .get_range(
                                &foundationdb::RangeOption {
                                    begin: foundationdb::KeySelector::first_greater_or_equal(
                                        &start_key,
                                    ),
                                    end: foundationdb::KeySelector::first_greater_or_equal(
                                        &end_key,
                                    ),
                                    limit: None,
                                    reverse: false,
                                    mode: foundationdb::StreamingMode::WantAll,
                                },
                                1,
                                false,
                            )
                            .await?;

                        for kv in range.iter() {
                            let unpacked: (String, String, String, String, u64) =
                                unpack(&kv.key()[index_subspace.bytes().len()..]).map_err(|e| {
                                    FdbError::from(format!("Failed to unpack: {}", e))
                                })?;

                            let (_prefix, user, relation, object, rev) = unpacked;

                            // Filter by revision
                            if rev > revision.0 {
                                continue;
                            }

                            // Deduplicate
                            let relationship_id = format!("{}:{}:{}", object, relation, user);
                            if seen.contains(&relationship_id) {
                                continue;
                            }
                            seen.insert(relationship_id);

                            // Check if active
                            let relationship_key =
                                relationships_subspace.pack(&(&object, &relation, &user, rev));
                            if let Some(value) = trx.get(&relationship_key, false).await? {
                                if &value == b"active" {
                                    relationships.push(Relationship {
                                        object,
                                        relation,
                                        user,
                                    });
                                }
                            }
                        }
                    }
                    // Only relation filter or no filters - scan all relationships
                    (None, Some(_), None) | (None, None, None) => {
                        // Full scan of relationships
                        let start_key = relationships_subspace.pack(&());
                        let end_key = relationships_subspace.pack(&("\u{10FFFF}",));

                        let range = trx
                            .get_range(
                                &foundationdb::RangeOption {
                                    begin: foundationdb::KeySelector::first_greater_or_equal(
                                        &start_key,
                                    ),
                                    end: foundationdb::KeySelector::first_greater_or_equal(
                                        &end_key,
                                    ),
                                    limit: None,
                                    reverse: false,
                                    mode: foundationdb::StreamingMode::WantAll,
                                },
                                1,
                                false,
                            )
                            .await?;

                        for kv in range.iter() {
                            let unpacked: (String, String, String, u64) = unpack(
                                &kv.key()[relationships_subspace.bytes().len()..],
                            )
                            .map_err(|e| FdbError::from(format!("Failed to unpack: {}", e)))?;

                            let (object, relation, user, rev) = unpacked;

                            // Filter by revision
                            if rev > revision.0 {
                                continue;
                            }

                            // Apply relation filter if needed
                            if let Some(ref filter_rel) = relation_filter {
                                if &relation != filter_rel {
                                    continue;
                                }
                            }

                            // Deduplicate
                            let relationship_id = format!("{}:{}:{}", object, relation, user);
                            if seen.contains(&relationship_id) {
                                continue;
                            }
                            seen.insert(relationship_id);

                            // Check if active
                            if &kv.value() == b"active" {
                                relationships.push(Relationship {
                                    object,
                                    relation,
                                    user,
                                });
                            }
                        }
                    }
                }

                Ok(relationships)
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to list relationships: {}", e)))?;

        debug!(
            "Listed {} relationships (filters: resource={:?}, relation={:?}, subject={:?})",
            result.len(),
            resource,
            relation,
            subject
        );
        Ok(result)
    }

    async fn append_change(&self, event: ChangeEvent) -> Result<()> {
        let db = Arc::clone(&self.db);
        let changelog_subspace = self.changelog_subspace.clone();

        let result = db
            .run(move |trx, _maybe_committed| async move {
                // Create key: (revision, timestamp, resource)
                // This allows efficient range queries starting from a revision
                let key = changelog_subspace.pack(&(
                    event.revision.0,
                    event.timestamp_nanos,
                    &event.relationship.resource,
                ));

                // Serialize the change event
                let value = serde_json::to_vec(&event).map_err(|e| {
                    FdbError::from(format!("Failed to serialize change event: {}", e))
                })?;

                trx.set(&key, &value);
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to append change: {}", e)))?;

        Ok(result)
    }

    async fn read_changes(
        &self,
        start_revision: Revision,
        resource_types: &[String],
        limit: Option<usize>,
    ) -> Result<Vec<ChangeEvent>> {
        let db = Arc::clone(&self.db);
        let changelog_subspace = self.changelog_subspace.clone();
        let resource_types = resource_types.to_vec();
        let max_count = limit.unwrap_or(usize::MAX);

        let result = db
            .run(move |trx, _maybe_committed| async move {
                // Create range starting from start_revision
                let start_key = changelog_subspace.pack(&(start_revision.0,));
                let end_key = changelog_subspace.pack(&(u64::MAX,));

                let range = trx
                    .get_range(
                        &foundationdb::RangeOption {
                            begin: foundationdb::KeySelector::first_greater_or_equal(&start_key),
                            end: foundationdb::KeySelector::first_greater_or_equal(&end_key),
                            limit: Some(max_count as i32),
                            reverse: false,
                            mode: foundationdb::StreamingMode::WantAll,
                        },
                        false,
                    )
                    .await?;

                let mut events = Vec::new();

                for kv in range {
                    let event: ChangeEvent = serde_json::from_slice(&kv.value()).map_err(|e| {
                        FdbError::from(format!("Failed to deserialize change event: {}", e))
                    })?;

                    // Filter by resource type if specified
                    if !resource_types.is_empty() {
                        if let Some(event_type) = event.resource_type() {
                            if !resource_types.iter().any(|t| t == event_type) {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }

                    events.push(event);

                    if events.len() >= max_count {
                        break;
                    }
                }

                Ok(events)
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to read changes: {}", e)))?;

        Ok(result)
    }

    async fn get_change_log_revision(&self) -> Result<Revision> {
        let db = Arc::clone(&self.db);
        let changelog_subspace = self.changelog_subspace.clone();

        let result = db
            .run(move |trx, _maybe_committed| async move {
                // Get the last key in the changelog
                let start_key = changelog_subspace.pack(&(u64::MAX,));
                let end_key = changelog_subspace.pack(&(0u64,));

                let range = trx
                    .get_range(
                        &foundationdb::RangeOption {
                            begin: foundationdb::KeySelector::first_greater_or_equal(&start_key),
                            end: foundationdb::KeySelector::first_greater_or_equal(&end_key),
                            limit: Some(1),
                            reverse: true, // Get last entry
                            mode: foundationdb::StreamingMode::WantAll,
                        },
                        false,
                    )
                    .await?;

                if let Some(kv) = range.first() {
                    let event: ChangeEvent = serde_json::from_slice(&kv.value()).map_err(|e| {
                        FdbError::from(format!("Failed to deserialize change event: {}", e))
                    })?;
                    Ok(event.revision)
                } else {
                    Ok(Revision::zero())
                }
            })
            .await
            .map_err(|e| {
                StoreError::Database(format!("Failed to get change log revision: {}", e))
            })?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running FoundationDB instance
    // They are marked with #[ignore] by default

    #[tokio::test]
    #[ignore]
    async fn test_fdb_connection() {
        let backend = FoundationDBBackend::new().await;
        assert!(backend.is_ok(), "Should connect to FDB");
    }

    #[tokio::test]
    #[ignore]
    async fn test_fdb_basic_operations() {
        let store = FoundationDBBackend::new().await.unwrap();

        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };

        // Write
        let rev = store.write(vec![relationship.clone()]).await.unwrap();

        // Read
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: None,
        };
        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subject, "user:alice");

        // Delete
        let del_rev = store.delete(&key).await.unwrap();
        let results = store.read(&key, del_rev).await.unwrap();
        assert_eq!(results.len(), 0);
    }
}
