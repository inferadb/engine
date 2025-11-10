//! FoundationDB storage backend
//!
//! Provides a production-ready storage backend using FoundationDB.
//! FoundationDB offers:
//! - ACID transactions
//! - Multi-version concurrency control (MVCC)
//! - Horizontal scalability
//! - High availability

#![allow(clippy::io_other_error)]

use std::sync::{Arc, Once};

use async_trait::async_trait;
use foundationdb::{
    Database, FdbBindingError, RangeOption,
    tuple::{Subspace, unpack},
};
use infera_types::{ChangeEvent, DeleteFilter, Relationship, RelationshipKey, Revision};
use serde_json;
use tracing::debug;
use uuid::Uuid;

use crate::{RelationshipStore, Result, StoreError};

// Global initialization flag for FDB network
// The FDB client library requires that select_api_version (called by boot())
// is only called once per process
static FDB_INIT: Once = Once::new();

/// FoundationDB storage backend
pub struct FoundationDBBackend {
    db: Arc<Database>,
    // Subspaces for organizing data
    relationships_subspace: Subspace,
    revision_subspace: Subspace,
    index_subspace: Subspace,
    changelog_subspace: Subspace,
}

#[allow(dead_code)]
impl FoundationDBBackend {
    /// Create a new FoundationDB backend
    pub async fn new() -> Result<Self> {
        Self::with_cluster_file(None).await
    }

    /// Create a new FoundationDB backend with a specific cluster file
    pub async fn with_cluster_file(cluster_file: Option<&str>) -> Result<Self> {
        // Initialize FDB API - only once per process
        // The FDB client library requires that select_api_version (called by boot())
        // is only called once per process. Using Once ensures thread-safe initialization.
        FDB_INIT.call_once(|| {
            let _network = unsafe { foundationdb::boot() };
            // The network handle is intentionally leaked here as it needs to live
            // for the entire process lifetime
            std::mem::forget(_network);
        });

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

    /// Get the current revision for a vault
    async fn get_current_revision(&self, vault: Uuid) -> Result<Revision> {
        let db = Arc::clone(&self.db);
        let revision_subspace = self.revision_subspace.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let revision_subspace = revision_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let revision_subspace = revision_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        let revision_key = revision_subspace.pack(&(vault_bytes, "current"));

                        match trx.get(&revision_key, false).await? {
                            Some(bytes) => {
                                let rev: u64 = serde_json::from_slice(&bytes).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to deserialize revision: {}", e),
                                        ),
                                    ))
                                })?;
                                Ok(Revision(rev))
                            },
                            None => Ok(Revision::zero()),
                        }
                    }
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to get revision: {}", e)))?;

        Ok(result)
    }

    /// Increment and return the next revision for a vault
    async fn increment_revision(&self, vault: Uuid) -> Result<Revision> {
        let db = Arc::clone(&self.db);
        let revision_subspace = self.revision_subspace.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let revision_subspace = revision_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let revision_subspace = revision_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        let revision_key = revision_subspace.pack(&(vault_bytes, "current"));

                        let current = match trx.get(&revision_key, false).await? {
                            Some(bytes) => {
                                let rev: u64 = serde_json::from_slice(&bytes).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to deserialize: {}", e),
                                        ),
                                    ))
                                })?;
                                rev
                            },
                            None => 0,
                        };

                        let next = current + 1;
                        let bytes = serde_json::to_vec(&next).map_err(|e| {
                            FdbBindingError::new_custom_error(Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Failed to serialize: {}", e),
                            )))
                        })?;

                        trx.set(&revision_key, &bytes);
                        Ok(Revision(next))
                    }
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to increment revision: {}", e)))?;

        Ok(result)
    }

    /// Create a key for a relationship with revision
    fn relationship_key(
        &self,
        vault: Uuid,
        relationship: &Relationship,
        revision: Revision,
    ) -> Vec<u8> {
        self.relationships_subspace.pack(&(
            vault.as_bytes().to_vec(),
            &relationship.resource,
            &relationship.relation,
            &relationship.subject,
            revision.0,
        ))
    }

    /// Create an index key for object/relation lookups
    fn index_key_object(
        &self,
        vault: Uuid,
        resource: &str,
        relation: &str,
        subject: &str,
        revision: Revision,
    ) -> Vec<u8> {
        self.index_subspace.pack(&(
            vault.as_bytes().to_vec(),
            "obj",
            resource,
            relation,
            subject,
            revision.0,
        ))
    }

    /// Create an index key for reverse lookups (user/relation)
    fn index_key_user(
        &self,
        vault: Uuid,
        subject: &str,
        relation: &str,
        resource: &str,
        revision: Revision,
    ) -> Vec<u8> {
        self.index_subspace.pack(&(
            vault.as_bytes().to_vec(),
            "user",
            subject,
            relation,
            resource,
            revision.0,
        ))
    }

    /// Parse a relationship from a key
    fn parse_relationship_from_key(&self, vault: Uuid, key: &[u8]) -> Result<Relationship> {
        let unpacked: (Vec<u8>, String, String, String, u64) =
            unpack(&key[self.relationships_subspace.bytes().len()..]).map_err(|e| {
                StoreError::Internal(format!("Failed to unpack relationship key: {}", e))
            })?;

        Ok(Relationship { vault, resource: unpacked.1, relation: unpacked.2, subject: unpacked.3 })
    }
}

#[async_trait]
impl RelationshipStore for FoundationDBBackend {
    async fn read(
        &self,
        vault: Uuid,
        key: &RelationshipKey,
        revision: Revision,
    ) -> Result<Vec<Relationship>> {
        let db = Arc::clone(&self.db);
        let object = key.resource.clone();
        let relation = key.relation.clone();
        let user_filter = key.subject.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        // Create range for this object+relation at or before the revision
        let index_subspace = self.index_subspace.clone();
        let start_key = index_subspace.pack(&(vault_bytes.clone(), "obj", &object, &relation));
        let end_key = index_subspace.pack(&(
            vault_bytes.clone(),
            "obj",
            &object,
            &relation,
            "\u{10FFFF}", // Max valid Unicode scalar value for range upper bound
        ));

        let relationships_subspace = self.relationships_subspace.clone();

        let result = db
            .run({
                let start_key = start_key.clone();
                let end_key = end_key.clone();
                let object = object.clone();
                let relation = relation.clone();
                let user_filter = user_filter.clone();
                let index_subspace = index_subspace.clone();
                let relationships_subspace = relationships_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let start_key = start_key.clone();
                    let end_key = end_key.clone();
                    let object = object.clone();
                    let relation = relation.clone();
                    let user_filter = user_filter.clone();
                    let index_subspace = index_subspace.clone();
                    let relationships_subspace = relationships_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        let range = trx
                            .get_range(
                                &RangeOption::from((start_key.as_slice(), end_key.as_slice())),
                                1,
                                false,
                            )
                            .await?;

                        // Track the latest revision for each relationship
                        let mut latest_revisions =
                            std::collections::HashMap::<String, (u64, String)>::new();

                        // Collect range into Vec of owned data before iterating to make it Send
                        let range_items: Vec<_> = range
                            .iter()
                            .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
                            .collect();
                        for (key, _value) in range_items {
                            let unpacked: (Vec<u8>, String, String, String, String, u64) =
                                unpack(&key[index_subspace.bytes().len()..]).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to unpack index: {}", e),
                                        ),
                                    ))
                                })?;

                            let (_vault_bytes, _prefix, _obj, _rel, user, rev) = unpacked;

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

                            // Track the latest revision for each relationship
                            let relationship_id = format!("{}:{}:{}", object, relation, user);
                            latest_revisions
                                .entry(relationship_id)
                                .and_modify(|(existing_rev, _)| {
                                    if rev > *existing_rev {
                                        *existing_rev = rev;
                                    }
                                })
                                .or_insert((rev, user.clone()));
                        }

                        // Now check each relationship at its latest revision to see if it's active
                        let mut relationships = Vec::new();
                        for (_relationship_id, (rev, user)) in latest_revisions {
                            let relationship_key = relationships_subspace.pack(&(
                                vault_bytes.clone(),
                                &object,
                                &relation,
                                &user,
                                rev,
                            ));
                            if let Some(relationship_value) =
                                trx.get(&relationship_key, false).await?
                            {
                                if relationship_value.as_ref() == b"active" {
                                    relationships.push(Relationship {
                                        vault,
                                        resource: object.clone(),
                                        relation: relation.clone(),
                                        subject: user.clone(),
                                    });
                                }
                            }
                        }

                        Ok(relationships)
                    }
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to read: {}", e)))?;

        debug!("Read {} relationships for {}:{}", result.len(), key.resource, key.relation);
        Ok(result)
    }

    async fn write(&self, vault: Uuid, relationships: Vec<Relationship>) -> Result<Revision> {
        if relationships.is_empty() {
            return self.get_current_revision(vault).await;
        }

        let relationships_len = relationships.len();
        let db = Arc::clone(&self.db);
        let relationships_subspace = self.relationships_subspace.clone();
        let index_subspace = self.index_subspace.clone();
        let revision_subspace = self.revision_subspace.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let relationships = relationships.clone();
                let relationships_subspace = relationships_subspace.clone();
                let index_subspace = index_subspace.clone();
                let revision_subspace = revision_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let relationships = relationships.clone();
                    let relationships_subspace = relationships_subspace.clone();
                    let index_subspace = index_subspace.clone();
                    let revision_subspace = revision_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        // Get and increment revision
                        let revision_key =
                            revision_subspace.pack(&(vault_bytes.clone(), "current"));
                        let current = match trx.get(&revision_key, false).await? {
                            Some(bytes) => {
                                let rev: u64 = serde_json::from_slice(&bytes).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to deserialize: {}", e),
                                        ),
                                    ))
                                })?;
                                rev
                            },
                            None => 0,
                        };

                        let next_rev = current + 1;
                        let rev_bytes = serde_json::to_vec(&next_rev).map_err(|e| {
                            FdbBindingError::new_custom_error(Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Failed to serialize: {}", e),
                            )))
                        })?;
                        trx.set(&revision_key, &rev_bytes);

                        let revision = Revision(next_rev);

                        // Write each relationship
                        for relationship in &relationships {
                            // Write relationship data
                            let relationship_key = relationships_subspace.pack(&(
                                vault_bytes.clone(),
                                &relationship.resource,
                                &relationship.relation,
                                &relationship.subject,
                                revision.0,
                            ));
                            trx.set(&relationship_key, b"active");

                            // Write index for object lookups
                            let obj_index = index_subspace.pack(&(
                                vault_bytes.clone(),
                                "obj",
                                &relationship.resource,
                                &relationship.relation,
                                &relationship.subject,
                                revision.0,
                            ));
                            trx.set(&obj_index, b"");

                            // Write index for reverse lookups
                            let subject_index = index_subspace.pack(&(
                                vault_bytes.clone(),
                                "user",
                                &relationship.subject,
                                &relationship.relation,
                                &relationship.resource,
                                revision.0,
                            ));
                            trx.set(&subject_index, b"");
                        }

                        Ok(revision)
                    }
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to write: {}", e)))?;

        debug!("Wrote {} relationships at revision {:?}", relationships_len, result);
        Ok(result)
    }

    async fn get_revision(&self, vault: Uuid) -> Result<Revision> {
        self.get_current_revision(vault).await
    }

    async fn delete(&self, vault: Uuid, key: &RelationshipKey) -> Result<Revision> {
        let db = Arc::clone(&self.db);
        let object = key.resource.clone();
        let relation = key.relation.clone();
        let user_filter = key.subject.clone();
        let relationships_subspace = self.relationships_subspace.clone();
        let revision_subspace = self.revision_subspace.clone();
        let index_subspace = self.index_subspace.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let object = object.clone();
                let relation = relation.clone();
                let user_filter = user_filter.clone();
                let relationships_subspace = relationships_subspace.clone();
                let revision_subspace = revision_subspace.clone();
                let index_subspace = index_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let object = object.clone();
                    let relation = relation.clone();
                    let user_filter = user_filter.clone();
                    let relationships_subspace = relationships_subspace.clone();
                    let revision_subspace = revision_subspace.clone();
                    let index_subspace = index_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        // Get and increment revision
                        let revision_key =
                            revision_subspace.pack(&(vault_bytes.clone(), "current"));
                        let current = match trx.get(&revision_key, false).await? {
                            Some(bytes) => {
                                let rev: u64 = serde_json::from_slice(&bytes).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to deserialize: {}", e),
                                        ),
                                    ))
                                })?;
                                rev
                            },
                            None => 0,
                        };

                        let next_rev = current + 1;
                        let rev_bytes = serde_json::to_vec(&next_rev).map_err(|e| {
                            FdbBindingError::new_custom_error(Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Failed to serialize: {}", e),
                            )))
                        })?;
                        trx.set(&revision_key, &rev_bytes);

                        let revision = Revision(next_rev);

                        // Mark matching relationships as deleted
                        if let Some(user) = user_filter {
                            // Delete specific relationship
                            let relationship_key = relationships_subspace.pack(&(
                                vault_bytes.clone(),
                                &object,
                                &relation,
                                &user,
                                revision.0,
                            ));
                            trx.set(&relationship_key, b"deleted");

                            // Create index entry for the deletion
                            let obj_index = index_subspace.pack(&(
                                vault_bytes.clone(),
                                "obj",
                                &object,
                                &relation,
                                &user,
                                revision.0,
                            ));
                            trx.set(&obj_index, b"");

                            let subject_index = index_subspace.pack(&(
                                vault_bytes.clone(),
                                "user",
                                &user,
                                &relation,
                                &object,
                                revision.0,
                            ));
                            trx.set(&subject_index, b"");
                        } else {
                            // Delete all relationships matching object+relation
                            // We write a deletion marker for each unique user we find
                            let start_key = relationships_subspace.pack(&(
                                vault_bytes.clone(),
                                &object,
                                &relation,
                            ));
                            let end_key = relationships_subspace.pack(&(
                                vault_bytes.clone(),
                                &object,
                                &relation,
                                "\u{10FFFF}",
                            ));

                            let range = trx
                                .get_range(
                                    &RangeOption::from((start_key.as_slice(), end_key.as_slice())),
                                    1,
                                    false,
                                )
                                .await?;

                            let mut deleted_users = std::collections::HashSet::new();
                            for kv in range.iter() {
                                let unpacked: (Vec<u8>, String, String, String, u64) =
                                    unpack(&kv.key()[relationships_subspace.bytes().len()..])
                                        .map_err(|e| {
                                            FdbBindingError::new_custom_error(Box::new(
                                                std::io::Error::new(
                                                    std::io::ErrorKind::Other,
                                                    format!("Failed to unpack: {}", e),
                                                ),
                                            ))
                                        })?;

                                let (_vault_bytes, _obj, _rel, user, _rev) = unpacked;
                                if !deleted_users.contains(&user) {
                                    deleted_users.insert(user.clone());
                                    let del_key = relationships_subspace.pack(&(
                                        vault_bytes.clone(),
                                        &object,
                                        &relation,
                                        &user,
                                        revision.0,
                                    ));
                                    trx.set(&del_key, b"deleted");

                                    // Create index entries for the deletion
                                    let obj_index = index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "obj",
                                        &object,
                                        &relation,
                                        &user,
                                        revision.0,
                                    ));
                                    trx.set(&obj_index, b"");

                                    let subject_index = index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "user",
                                        &user,
                                        &relation,
                                        &object,
                                        revision.0,
                                    ));
                                    trx.set(&subject_index, b"");
                                }
                            }
                        }

                        Ok(revision)
                    }
                }
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
        vault: Uuid,
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
        let revision_subspace = self.revision_subspace.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let filter = filter.clone();
                let relationships_subspace = relationships_subspace.clone();
                let revision_subspace = revision_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let filter = filter.clone();
                    let relationships_subspace = relationships_subspace.clone();
                    let revision_subspace = revision_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        // Get and increment revision
                        let revision_key =
                            revision_subspace.pack(&(vault_bytes.clone(), "current"));
                        let current = match trx.get(&revision_key, false).await? {
                            Some(bytes) => {
                                let rev: u64 = serde_json::from_slice(&bytes).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to deserialize: {}", e),
                                        ),
                                    ))
                                })?;
                                rev
                            },
                            None => 0,
                        };

                        let next_rev = current + 1;
                        let rev_bytes = serde_json::to_vec(&next_rev).map_err(|e| {
                            FdbBindingError::new_custom_error(Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Failed to serialize: {}", e),
                            )))
                        })?;
                        trx.set(&revision_key, &rev_bytes);

                        let revision = Revision(next_rev);

                        // Scan all relationships in this vault and match against filter
                        let start_key = relationships_subspace.pack(&(vault_bytes.clone(),));
                        let end_key =
                            relationships_subspace.pack(&(vault_bytes.clone(), "\u{10FFFF}"));

                        let range = trx
                            .get_range(
                                &RangeOption::from((start_key.as_slice(), end_key.as_slice())),
                                1,
                                false,
                            )
                            .await?;

                        let mut deleted_count = 0;
                        // Use owned Strings to avoid lifetime issues
                        let mut deleted_keys: std::collections::HashSet<(String, String, String)> =
                            std::collections::HashSet::new();

                        // Collect range into Vec of owned data before iterating to make it Send
                        let range_items: Vec<_> = range
                            .iter()
                            .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
                            .collect();
                        for (key, value) in range_items {
                            // Skip if already at limit
                            if let Some(lim) = limit {
                                if lim > 0 && deleted_count >= lim {
                                    break;
                                }
                            }

                            let unpacked: (Vec<u8>, String, String, String, u64) = unpack(
                                &key[relationships_subspace.bytes().len()..],
                            )
                            .map_err(|e| {
                                FdbBindingError::new_custom_error(Box::new(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!("Failed to unpack: {}", e),
                                )))
                            })?;

                            let (_vault_bytes, resource, relation, subject, _rev) = unpacked;

                            // Skip if already marked as deleted
                            if value.as_slice() == b"deleted" {
                                continue;
                            }

                            // Check filter conditions
                            let matches =
                                match (&filter.resource, &filter.relation, &filter.subject) {
                                    // All three specified (exact match)
                                    (Some(res), Some(rel_name), Some(sub)) => {
                                        resource == *res && relation == *rel_name && subject == *sub
                                    },
                                    // Resource + Relation
                                    (Some(res), Some(rel_name), None) => {
                                        resource == *res && relation == *rel_name
                                    },
                                    // Resource + Subject
                                    (Some(res), None, Some(sub)) => {
                                        resource == *res && subject == *sub
                                    },
                                    // Relation + Subject
                                    (None, Some(rel_name), Some(sub)) => {
                                        relation == *rel_name && subject == *sub
                                    },
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
                                let unique_key =
                                    (resource.clone(), relation.clone(), subject.clone());
                                if !deleted_keys.contains(&unique_key) {
                                    deleted_keys.insert(unique_key.clone());

                                    // Write deletion marker at new revision
                                    let del_key = relationships_subspace.pack(&(
                                        vault_bytes.clone(),
                                        &unique_key.0,
                                        &unique_key.1,
                                        &unique_key.2,
                                        revision.0,
                                    ));
                                    trx.set(&del_key, b"deleted");
                                    deleted_count += 1;
                                }
                            }
                        }

                        Ok((revision, deleted_count))
                    }
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to delete by filter: {}", e)))?;

        debug!("Deleted {} relationships matching filter at revision {:?}", result.1, result.0);
        Ok(result)
    }

    async fn list_resources_by_type(
        &self,
        vault: Uuid,
        object_type: &str,
        revision: Revision,
    ) -> Result<Vec<String>> {
        let db = Arc::clone(&self.db);
        let object_type = object_type.to_string();
        let index_subspace = self.index_subspace.clone();
        let relationships_subspace = self.relationships_subspace.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        // Build the type prefix (e.g., "document:")
        let type_prefix = format!("{}:", object_type);
        let type_end = format!("{};\u{0}", object_type); // Next string after "type:"

        let result = db
            .run({
                let type_prefix = type_prefix.clone();
                let type_end = type_end.clone();
                let index_subspace = index_subspace.clone();
                let relationships_subspace = relationships_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let type_prefix = type_prefix.clone();
                    let type_end = type_end.clone();
                    let index_subspace = index_subspace.clone();
                    let relationships_subspace = relationships_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        // Query range of all objects with this type prefix
                        let start_key = index_subspace.pack(&(
                            vault_bytes.clone(),
                            "obj",
                            type_prefix.as_str(),
                        ));
                        let end_key =
                            index_subspace.pack(&(vault_bytes.clone(), "obj", type_end.as_str()));

                        let range = trx
                            .get_range(
                                &RangeOption::from((start_key.as_slice(), end_key.as_slice())),
                                1,
                                false,
                            )
                            .await?;

                        let mut objects = std::collections::HashSet::new();

                        // Collect range into Vec of owned data before iterating to make it Send
                        let range_items: Vec<_> = range
                            .iter()
                            .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
                            .collect();
                        for (key, _value) in range_items {
                            // Unpack: (vault_bytes, "obj", object, relation, user, rev)
                            let unpacked: (Vec<u8>, String, String, String, String, u64) =
                                unpack(&key[index_subspace.bytes().len()..]).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to unpack index: {}", e),
                                        ),
                                    ))
                                })?;

                            let (_vault_bytes, _prefix, object, relation, user, rev) = unpacked;

                            // Only include relationships at or before requested revision
                            if rev > revision.0 {
                                continue;
                            }

                            // Check if this relationship is still active at the requested revision
                            let relationship_key = relationships_subspace.pack(&(
                                vault_bytes.clone(),
                                &object,
                                &relation,
                                &user,
                                rev,
                            ));
                            if let Some(value) = trx.get(&relationship_key, false).await? {
                                if value.as_ref() == b"active" {
                                    objects.insert(object);
                                }
                            }
                        }

                        // Convert to sorted vector for deterministic output
                        let mut result: Vec<String> = objects.into_iter().collect();
                        result.sort();

                        Ok(result)
                    }
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to list objects by type: {}", e)))?;

        debug!("Listed {} objects of type '{}'", result.len(), object_type);
        Ok(result)
    }

    async fn list_relationships(
        &self,
        vault: Uuid,
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
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let object_filter = object_filter.clone();
                let relation_filter = relation_filter.clone();
                let user_filter = user_filter.clone();
                let index_subspace = index_subspace.clone();
                let relationships_subspace = relationships_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let object_filter = object_filter.clone();
                    let relation_filter = relation_filter.clone();
                    let user_filter = user_filter.clone();
                    let index_subspace = index_subspace.clone();
                    let relationships_subspace = relationships_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        let mut relationships = Vec::new();
                        let mut seen = std::collections::HashSet::new();

                        // Determine the best index to use based on provided filters
                        match (&object_filter, &relation_filter, &user_filter) {
                            // Use object index when we have object filter
                            (Some(obj), _rel, _) => {
                                let start_key = if let Some(rel) = &relation_filter {
                                    index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "obj",
                                        obj.as_str(),
                                        rel.as_str(),
                                    ))
                                } else {
                                    index_subspace.pack(&(vault_bytes.clone(), "obj", obj.as_str()))
                                };
                                let end_key = if let Some(rel) = &relation_filter {
                                    index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "obj",
                                        obj.as_str(),
                                        rel.as_str(),
                                        "\u{10FFFF}",
                                    ))
                                } else {
                                    index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "obj",
                                        obj.as_str(),
                                        "\u{10FFFF}",
                                    ))
                                };

                                let range = trx
                                    .get_range(
                                        &RangeOption::from((
                                            start_key.as_slice(),
                                            end_key.as_slice(),
                                        )),
                                        1,
                                        false,
                                    )
                                    .await?;

                                // Collect range into Vec of owned data before iterating to make it
                                // Send
                                let range_items: Vec<_> = range
                                    .iter()
                                    .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
                                    .collect();
                                for (key, _value) in range_items {
                                    let unpacked: (Vec<u8>, String, String, String, String, u64) =
                                        unpack(&key[index_subspace.bytes().len()..]).map_err(
                                            |e| {
                                                FdbBindingError::new_custom_error(Box::new(
                                                    std::io::Error::new(
                                                        std::io::ErrorKind::Other,
                                                        format!("Failed to unpack: {}", e),
                                                    ),
                                                ))
                                            },
                                        )?;

                                    let (_vault_bytes, _prefix, object, relation, user, rev) =
                                        unpacked;

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
                                    let relationship_id =
                                        format!("{}:{}:{}", object, relation, user);
                                    if seen.contains(&relationship_id) {
                                        continue;
                                    }
                                    seen.insert(relationship_id);

                                    // Check if active
                                    let relationship_key = relationships_subspace.pack(&(
                                        vault_bytes.clone(),
                                        &object,
                                        &relation,
                                        &user,
                                        rev,
                                    ));
                                    if let Some(relationship_value) =
                                        trx.get(&relationship_key, false).await?
                                    {
                                        if relationship_value.as_ref() == b"active" {
                                            relationships.push(Relationship {
                                                vault,
                                                resource: object,
                                                relation,
                                                subject: user,
                                            });
                                        }
                                    }
                                }
                            },
                            // Use user index when we have user filter (but no object filter)
                            (None, _rel, Some(usr)) => {
                                let start_key = if let Some(rel) = &relation_filter {
                                    index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "user",
                                        usr.as_str(),
                                        rel.as_str(),
                                    ))
                                } else {
                                    index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "user",
                                        usr.as_str(),
                                    ))
                                };
                                let end_key = if let Some(rel) = &relation_filter {
                                    index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "user",
                                        usr.as_str(),
                                        rel.as_str(),
                                        "\u{10FFFF}",
                                    ))
                                } else {
                                    index_subspace.pack(&(
                                        vault_bytes.clone(),
                                        "user",
                                        usr.as_str(),
                                        "\u{10FFFF}",
                                    ))
                                };

                                let range = trx
                                    .get_range(
                                        &RangeOption::from((
                                            start_key.as_slice(),
                                            end_key.as_slice(),
                                        )),
                                        1,
                                        false,
                                    )
                                    .await?;

                                // Collect range into Vec of owned data before iterating to make it
                                // Send
                                let range_items: Vec<_> = range
                                    .iter()
                                    .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
                                    .collect();
                                for (key, _value) in range_items {
                                    let unpacked: (Vec<u8>, String, String, String, String, u64) =
                                        unpack(&key[index_subspace.bytes().len()..]).map_err(
                                            |e| {
                                                FdbBindingError::new_custom_error(Box::new(
                                                    std::io::Error::new(
                                                        std::io::ErrorKind::Other,
                                                        format!("Failed to unpack: {}", e),
                                                    ),
                                                ))
                                            },
                                        )?;

                                    let (_vault_bytes, _prefix, user, relation, object, rev) =
                                        unpacked;

                                    // Filter by revision
                                    if rev > revision.0 {
                                        continue;
                                    }

                                    // Deduplicate
                                    let relationship_id =
                                        format!("{}:{}:{}", object, relation, user);
                                    if seen.contains(&relationship_id) {
                                        continue;
                                    }
                                    seen.insert(relationship_id);

                                    // Check if active
                                    let relationship_key = relationships_subspace.pack(&(
                                        vault_bytes.clone(),
                                        &object,
                                        &relation,
                                        &user,
                                        rev,
                                    ));
                                    if let Some(relationship_value) =
                                        trx.get(&relationship_key, false).await?
                                    {
                                        if relationship_value.as_ref() == b"active" {
                                            relationships.push(Relationship {
                                                vault,
                                                resource: object,
                                                relation,
                                                subject: user,
                                            });
                                        }
                                    }
                                }
                            },
                            // Only relation filter or no filters - scan all relationships
                            (None, Some(_), None) | (None, None, None) => {
                                // Full scan of relationships in this vault
                                let start_key =
                                    relationships_subspace.pack(&(vault_bytes.clone(),));
                                let end_key = relationships_subspace
                                    .pack(&(vault_bytes.clone(), "\u{10FFFF}"));

                                let range = trx
                                    .get_range(
                                        &RangeOption::from((
                                            start_key.as_slice(),
                                            end_key.as_slice(),
                                        )),
                                        1,
                                        false,
                                    )
                                    .await?;

                                // Collect range into Vec of owned data before iterating to make it
                                // Send
                                let range_items: Vec<_> = range
                                    .iter()
                                    .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
                                    .collect();
                                for (key, value) in range_items {
                                    let unpacked: (Vec<u8>, String, String, String, u64) =
                                        unpack(&key[relationships_subspace.bytes().len()..])
                                            .map_err(|e| {
                                                FdbBindingError::new_custom_error(Box::new(
                                                    std::io::Error::new(
                                                        std::io::ErrorKind::Other,
                                                        format!("Failed to unpack: {}", e),
                                                    ),
                                                ))
                                            })?;

                                    let (_vault_bytes, object, relation, user, rev) = unpacked;

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
                                    let relationship_id =
                                        format!("{}:{}:{}", object, relation, user);
                                    if seen.contains(&relationship_id) {
                                        continue;
                                    }
                                    seen.insert(relationship_id);

                                    // Check if active
                                    if value.as_slice() == b"active" {
                                        relationships.push(Relationship {
                                            vault,
                                            resource: object,
                                            relation,
                                            subject: user,
                                        });
                                    }
                                }
                            },
                        }

                        Ok(relationships)
                    }
                }
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

    async fn append_change(&self, vault: Uuid, event: ChangeEvent) -> Result<()> {
        let db = Arc::clone(&self.db);
        let changelog_subspace = self.changelog_subspace.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let event = event.clone();
                let changelog_subspace = changelog_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let event = event.clone();
                    let changelog_subspace = changelog_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        // Create key: (vault, revision, timestamp, resource)
                        // This allows efficient range queries starting from a revision
                        let key = changelog_subspace.pack(&(
                            vault_bytes,
                            event.revision.0,
                            event.timestamp_nanos,
                            &event.relationship.resource,
                        ));

                        // Serialize the change event
                        let value = serde_json::to_vec(&event).map_err(|e| {
                            FdbBindingError::new_custom_error(Box::new(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Failed to serialize change event: {}", e),
                            )))
                        })?;

                        trx.set(&key, &value);
                        Ok(())
                    }
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to append change: {}", e)))?;

        Ok(result)
    }

    async fn read_changes(
        &self,
        vault: Uuid,
        start_revision: Revision,
        resource_types: &[String],
        limit: Option<usize>,
    ) -> Result<Vec<ChangeEvent>> {
        let db = Arc::clone(&self.db);
        let changelog_subspace = self.changelog_subspace.clone();
        let resource_types = resource_types.to_vec();
        let max_count = limit.unwrap_or(usize::MAX);
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let resource_types = resource_types.clone();
                let changelog_subspace = changelog_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let resource_types = resource_types.clone();
                    let changelog_subspace = changelog_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        // Create range starting from start_revision for this vault
                        let start_key =
                            changelog_subspace.pack(&(vault_bytes.clone(), start_revision.0));
                        let end_key = changelog_subspace.pack(&(vault_bytes.clone(), u64::MAX));

                        let range = trx
                            .get_range(
                                &RangeOption::from((start_key.as_slice(), end_key.as_slice())),
                                1,
                                false,
                            )
                            .await?;

                        let mut events = Vec::new();

                        // Collect range into Vec before iterating to make it Send
                        let range_items: Vec<_> = range.iter().collect();
                        for kv in range_items {
                            let event: ChangeEvent =
                                serde_json::from_slice(kv.value()).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to deserialize change event: {}", e),
                                        ),
                                    ))
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
                    }
                }
            })
            .await
            .map_err(|e| StoreError::Database(format!("Failed to read changes: {}", e)))?;

        Ok(result)
    }

    async fn get_change_log_revision(&self, vault: Uuid) -> Result<Revision> {
        let db = Arc::clone(&self.db);
        let changelog_subspace = self.changelog_subspace.clone();
        let vault_bytes = vault.as_bytes().to_vec();

        let result = db
            .run({
                let changelog_subspace = changelog_subspace.clone();
                let vault_bytes = vault_bytes.clone();
                move |trx, _maybe_committed| {
                    let changelog_subspace = changelog_subspace.clone();
                    let vault_bytes = vault_bytes.clone();
                    async move {
                        // Get the last key in the changelog for this vault
                        let start_key = changelog_subspace.pack(&(vault_bytes.clone(), u64::MAX));
                        let end_key = changelog_subspace.pack(&(vault_bytes.clone(), 0u64));

                        let range = trx
                            .get_range(
                                &RangeOption::from((start_key.as_slice(), end_key.as_slice()))
                                    .rev(),
                                1,
                                false,
                            )
                            .await?;

                        if let Some(kv) = range.first() {
                            let event: ChangeEvent =
                                serde_json::from_slice(kv.value()).map_err(|e| {
                                    FdbBindingError::new_custom_error(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            format!("Failed to deserialize change event: {}", e),
                                        ),
                                    ))
                                })?;
                            Ok(event.revision)
                        } else {
                            Ok(Revision::zero())
                        }
                    }
                }
            })
            .await
            .map_err(|e| {
                StoreError::Database(format!("Failed to get change log revision: {}", e))
            })?;

        Ok(result)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(all(test, feature = "fdb-integration-tests"))]
mod tests {
    use super::*;

    /// FoundationDB Integration Tests
    ///
    /// These tests require a running FoundationDB instance.
    /// To run them, use:
    ///
    /// ```bash
    /// # Start FoundationDB first (e.g., via Docker)
    /// docker run -p 4500:4500 foundationdb/foundationdb:7.3.69
    ///
    /// # Run tests with the feature flag
    /// cargo test -p infera-store --features fdb-integration-tests
    /// ```

    #[tokio::test]
    async fn test_fdb_connection() {
        let backend = FoundationDBBackend::new().await;
        assert!(backend.is_ok(), "Should connect to FDB");
    }

    #[tokio::test]
    async fn test_fdb_basic_operations() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        let relationship = Relationship {
            vault,
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };

        // Write
        let rev = store.write(vault, vec![relationship.clone()]).await.unwrap();

        // Read
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: None,
        };
        let results = store.read(vault, &key, rev).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subject, "user:alice");

        // Delete
        let del_rev = store.delete(vault, &key).await.unwrap();
        let results = store.read(vault, &key, del_rev).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_vault_isolation() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault_a = Uuid::new_v4();
        let vault_b = Uuid::new_v4();

        // Write to vault A
        let rel_a = Relationship {
            vault: vault_a,
            resource: "doc:secret".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        let rev_a = store.write(vault_a, vec![rel_a.clone()]).await.unwrap();

        // Write to vault B
        let rel_b = Relationship {
            vault: vault_b,
            resource: "doc:secret".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
        };
        let rev_b = store.write(vault_b, vec![rel_b.clone()]).await.unwrap();

        // Verify vault A can only see its own data
        let key = RelationshipKey {
            resource: "doc:secret".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let results_a = store.read(vault_a, &key, rev_a).await.unwrap();
        assert_eq!(results_a.len(), 1, "Vault A should see 1 relationship");
        assert_eq!(results_a[0].subject, "user:alice");

        // Verify vault B can only see its own data
        let results_b = store.read(vault_b, &key, rev_b).await.unwrap();
        assert_eq!(results_b.len(), 1, "Vault B should see 1 relationship");
        assert_eq!(results_b[0].subject, "user:bob");

        // Critical: Verify vault A cannot see vault B's data
        let results_cross = store.read(vault_a, &key, rev_b).await.unwrap();
        assert_eq!(results_cross.len(), 1, "Vault A should still only see alice");
        assert_eq!(results_cross[0].subject, "user:alice");

        // Critical: Verify vault B cannot see vault A's data
        let results_cross2 = store.read(vault_b, &key, rev_a).await.unwrap();
        assert_eq!(results_cross2.len(), 1, "Vault B should still only see bob");
        assert_eq!(results_cross2[0].subject, "user:bob");
    }

    #[tokio::test]
    async fn test_revision_mvcc() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        let key = RelationshipKey {
            resource: "doc:history".to_string(),
            relation: "editor".to_string(),
            subject: None,
        };

        // Rev 1: Write alice
        let rel1 = Relationship {
            vault,
            resource: "doc:history".to_string(),
            relation: "editor".to_string(),
            subject: "user:alice".to_string(),
        };
        let rev1 = store.write(vault, vec![rel1]).await.unwrap();

        // Rev 2: Add bob
        let rel2 = Relationship {
            vault,
            resource: "doc:history".to_string(),
            relation: "editor".to_string(),
            subject: "user:bob".to_string(),
        };
        let rev2 = store.write(vault, vec![rel2]).await.unwrap();

        // Rev 3: Delete alice
        let del_key = RelationshipKey {
            resource: "doc:history".to_string(),
            relation: "editor".to_string(),
            subject: Some("user:alice".to_string()),
        };
        let rev3 = store.delete(vault, &del_key).await.unwrap();

        // Time travel: Read at rev1 should show only alice
        let results_at_rev1 = store.read(vault, &key, rev1).await.unwrap();
        assert_eq!(results_at_rev1.len(), 1, "At rev1 should have 1 user");
        assert_eq!(results_at_rev1[0].subject, "user:alice");

        // Time travel: Read at rev2 should show alice and bob
        let results_at_rev2 = store.read(vault, &key, rev2).await.unwrap();
        assert_eq!(results_at_rev2.len(), 2, "At rev2 should have 2 users");
        let subjects: Vec<_> = results_at_rev2.iter().map(|r| r.subject.as_str()).collect();
        assert!(subjects.contains(&"user:alice"));
        assert!(subjects.contains(&"user:bob"));

        // Time travel: Read at rev3 should show only bob
        let results_at_rev3 = store.read(vault, &key, rev3).await.unwrap();
        assert_eq!(results_at_rev3.len(), 1, "At rev3 should have 1 user");
        assert_eq!(results_at_rev3[0].subject, "user:bob");
    }

    #[tokio::test]
    async fn test_delete_by_filter_resource_only() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        // Setup: Create multiple relationships for same resource
        let rels = vec![
            Relationship {
                vault,
                resource: "doc:delete_me".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "doc:delete_me".to_string(),
                relation: "editor".to_string(),
                subject: "user:bob".to_string(),
            },
            Relationship {
                vault,
                resource: "doc:keep_me".to_string(),
                relation: "viewer".to_string(),
                subject: "user:charlie".to_string(),
            },
        ];
        store.write(vault, rels).await.unwrap();

        // Delete all relationships for doc:delete_me
        let filter = DeleteFilter {
            resource: Some("doc:delete_me".to_string()),
            relation: None,
            subject: None,
        };
        let (rev, count) = store.delete_by_filter(vault, &filter, None).await.unwrap();
        assert_eq!(count, 2, "Should delete 2 relationships");

        // Verify doc:delete_me relationships are gone
        let key = RelationshipKey {
            resource: "doc:delete_me".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let results = store.read(vault, &key, rev).await.unwrap();
        assert_eq!(results.len(), 0, "doc:delete_me should have no relationships");

        // Verify doc:keep_me is still there
        let key2 = RelationshipKey {
            resource: "doc:keep_me".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let results2 = store.read(vault, &key2, rev).await.unwrap();
        assert_eq!(results2.len(), 1, "doc:keep_me should still exist");
    }

    #[tokio::test]
    async fn test_delete_by_filter_subject_only() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        // Setup: User alice has multiple permissions
        let rels = vec![
            Relationship {
                vault,
                resource: "doc:1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "doc:2".to_string(),
                relation: "editor".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "doc:1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
            },
        ];
        store.write(vault, rels).await.unwrap();

        // User offboarding: Delete all alice's relationships
        let filter = DeleteFilter {
            resource: None,
            relation: None,
            subject: Some("user:alice".to_string()),
        };
        let (rev, count) = store.delete_by_filter(vault, &filter, None).await.unwrap();
        assert_eq!(count, 2, "Should delete alice's 2 relationships");

        // Verify alice has no relationships
        let key = RelationshipKey {
            resource: "doc:1".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let results = store.read(vault, &key, rev).await.unwrap();
        assert_eq!(results.len(), 1, "Should only have bob now");
        assert_eq!(results[0].subject, "user:bob");
    }

    #[tokio::test]
    async fn test_delete_by_filter_with_limit() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        // Setup: Create 5 relationships with same resource
        let rels: Vec<_> = (1..=5)
            .map(|i| Relationship {
                vault,
                resource: "doc:limited".to_string(),
                relation: "viewer".to_string(),
                subject: format!("user:{}", i),
            })
            .collect();
        store.write(vault, rels).await.unwrap();

        // Delete with limit of 3
        let filter = DeleteFilter {
            resource: Some("doc:limited".to_string()),
            relation: Some("viewer".to_string()),
            subject: None,
        };
        let (rev, count) = store.delete_by_filter(vault, &filter, Some(3)).await.unwrap();
        assert_eq!(count, 3, "Should delete exactly 3 relationships");

        // Verify only 2 remain
        let key = RelationshipKey {
            resource: "doc:limited".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let results = store.read(vault, &key, rev).await.unwrap();
        assert_eq!(results.len(), 2, "Should have 2 relationships remaining");
    }

    #[tokio::test]
    async fn test_delete_by_filter_empty_filter() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        // Empty filter should error
        let filter = DeleteFilter {
            resource: None,
            relation: None,
            subject: None,
        };
        let result = store.delete_by_filter(vault, &filter, None).await;
        assert!(result.is_err(), "Empty filter should return error");
    }

    #[tokio::test]
    async fn test_index_consistency_after_delete() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        // Write a relationship
        let rel = Relationship {
            vault,
            resource: "doc:indexed".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        let write_rev = store.write(vault, vec![rel]).await.unwrap();

        // Verify we can read it (index is working)
        let key = RelationshipKey {
            resource: "doc:indexed".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let results = store.read(vault, &key, write_rev).await.unwrap();
        assert_eq!(results.len(), 1, "Should find relationship via index");

        // Delete the relationship
        let del_rev = store.delete(vault, &key).await.unwrap();

        // Critical: Index should reflect deletion
        let results_after = store.read(vault, &key, del_rev).await.unwrap();
        assert_eq!(results_after.len(), 0, "Index should show relationship deleted");

        // Verify at different revision numbers
        let current_rev = store.get_revision(vault).await.unwrap();
        let results_at_current = store.read(vault, &key, current_rev).await.unwrap();
        assert_eq!(results_at_current.len(), 0, "Should still show deleted at current rev");
    }

    #[tokio::test]
    async fn test_bulk_write_operations() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        // Write multiple relationships in one transaction
        let rels: Vec<_> = (1..=10)
            .map(|i| Relationship {
                vault,
                resource: format!("doc:{}", i),
                relation: "owner".to_string(),
                subject: "user:admin".to_string(),
            })
            .collect();

        let rev = store.write(vault, rels).await.unwrap();

        // Verify all were written
        for i in 1..=10 {
            let key = RelationshipKey {
                resource: format!("doc:{}", i),
                relation: "owner".to_string(),
                subject: None,
            };
            let results = store.read(vault, &key, rev).await.unwrap();
            assert_eq!(results.len(), 1, "Doc {} should have owner", i);
            assert_eq!(results[0].subject, "user:admin");
        }
    }

    #[tokio::test]
    async fn test_read_query_variations() {
        let store = FoundationDBBackend::new().await.unwrap();
        let vault = Uuid::new_v4();

        // Setup diverse relationships
        let rels = vec![
            Relationship {
                vault,
                resource: "doc:1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "doc:1".to_string(),
                relation: "editor".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "doc:2".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                vault,
                resource: "doc:1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
            },
        ];
        let rev = store.write(vault, rels).await.unwrap();

        // Query 1: Specific resource + relation
        let key1 = RelationshipKey {
            resource: "doc:1".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let results1 = store.read(vault, &key1, rev).await.unwrap();
        assert_eq!(results1.len(), 2, "doc:1 viewers should be alice and bob");

        // Query 2: Specific resource + relation + subject
        let key2 = RelationshipKey {
            resource: "doc:1".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        let results2 = store.read(vault, &key2, rev).await.unwrap();
        assert_eq!(results2.len(), 1, "Should find exact match");
        assert_eq!(results2[0].subject, "user:alice");

        // Query 3: Resource only (all relations)
        let key3 = RelationshipKey {
            resource: "doc:1".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let results3 = store.read(vault, &key3, rev).await.unwrap();
        assert!(results3.len() >= 2, "doc:1 should have multiple relationships");
    }
}
