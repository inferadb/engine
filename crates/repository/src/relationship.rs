//! Repository for Relationship entity operations.
//!
//! This module provides [`RelationshipRepository`] which handles authorization graph
//! storage operations using a generic [`StorageBackend`].
//!
//! # Key Schema
//!
//! - `engine:rel:{vault}:{resource}:{relation}:{subject}` → JSON-serialized versioned relationship
//! - `engine:rel:rev:{vault}` → current revision (u64 as le_bytes)
//! - `engine:changelog:{vault}:{revision:020}` → JSON-serialized ChangeEvent
//!
//! # Storage Model
//!
//! Unlike simple CRUD repositories, RelationshipRepository uses a **versioned** model:
//! - Each relationship is stored with `created_at` and optional `deleted_at` revisions
//! - Reads at a specific revision return relationships visible at that point in time
//! - Writes increment the vault revision and store new relationships
//! - Deletes mark relationships with `deleted_at` instead of physically removing them
//!
//! # Revision Handling
//!
//! - Each write/delete increments the vault's revision counter
//! - Relationships are versioned (created_at, deleted_at revisions)
//! - Reads can specify a revision for point-in-time queries

use std::collections::HashSet;

use inferadb_common_storage::StorageBackend;
use inferadb_engine_types::{ChangeEvent, DeleteFilter, Relationship, RelationshipKey, Revision};
use serde::{Deserialize, Serialize};

use crate::{
    error::{RepositoryError, RepositoryResult},
    keys,
};

/// A versioned relationship with its creation and deletion revisions.
///
/// This is the internal storage format that tracks when relationships
/// were created and optionally deleted, enabling point-in-time queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionedRelationship {
    /// The underlying relationship data.
    relationship: Relationship,
    /// Revision at which this relationship was created.
    created_at: Revision,
    /// Revision at which this relationship was deleted (if any).
    deleted_at: Option<Revision>,
}

impl VersionedRelationship {
    /// Creates a new versioned relationship.
    fn new(relationship: Relationship, created_at: Revision) -> Self {
        Self { relationship, created_at, deleted_at: None }
    }

    /// Returns true if this relationship is visible at the given revision.
    ///
    /// A relationship is visible if:
    /// - It was created at or before the query revision
    /// - It has not been deleted, OR was deleted after the query revision
    fn is_visible_at(&self, revision: Revision) -> bool {
        if self.created_at > revision {
            return false;
        }
        match self.deleted_at {
            None => true,
            Some(deleted) => deleted > revision,
        }
    }
}

/// Repository for Relationship (authorization graph) operations.
///
/// Provides versioned CRUD operations for the authorization graph with
/// support for point-in-time queries and change log tracking.
///
/// # Type Parameters
///
/// * `S` - A type implementing [`StorageBackend`] for underlying storage operations.
///
/// # Revision Semantics
///
/// All write operations increment the vault's revision counter. Read operations
/// accept a [`Revision`] parameter to enable consistent reads at a specific
/// point in time.
///
/// # Example
///
/// ```ignore
/// use inferadb_common_storage::MemoryBackend;
/// use inferadb_engine_repository::RelationshipRepository;
///
/// let storage = MemoryBackend::new();
/// let repo = RelationshipRepository::new(storage);
/// ```
pub struct RelationshipRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> RelationshipRepository<S> {
    /// Create a new relationship repository with the given storage backend.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Build the storage key for a relationship (without revision in key).
    ///
    /// Schema: `engine:rel:{vault}:{resource}:{relation}:{subject}`
    fn relationship_key(vault: i64, resource: &str, relation: &str, subject: &str) -> Vec<u8> {
        format!("engine:rel:{}:{}:{}:{}", vault, resource, relation, subject).into_bytes()
    }

    /// Build the storage key prefix for scanning all relationships in a vault.
    fn vault_relationships_prefix(vault: i64) -> Vec<u8> {
        format!("engine:rel:{}:", vault).into_bytes()
    }

    /// Build the storage key end for scanning all relationships in a vault.
    fn vault_relationships_end(vault: i64) -> Vec<u8> {
        format!("engine:rel:{}~", vault).into_bytes()
    }

    /// Get the current revision for a vault, or zero if not set.
    async fn get_current_revision(&self, vault: i64) -> RepositoryResult<Revision> {
        let key = keys::relationship::revision(vault);
        match self.storage.get(&key).await? {
            Some(bytes) => {
                let Ok(arr): Result<[u8; 8], _> = bytes[..].try_into() else {
                    return Ok(Revision::zero());
                };
                Ok(Revision(u64::from_le_bytes(arr)))
            },
            None => Ok(Revision::zero()),
        }
    }

    /// Increment and store the vault revision, returning the new revision.
    async fn increment_revision(&self, vault: i64) -> RepositoryResult<Revision> {
        let current = self.get_current_revision(vault).await?;
        let new_rev = current.next();
        let key = keys::relationship::revision(vault);
        self.storage.set(key, new_rev.0.to_le_bytes().to_vec()).await?;
        Ok(new_rev)
    }

    /// Read relationships matching the key at a specific revision.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault containing the relationships.
    /// * `key` - The relationship key to match.
    /// * `revision` - The revision to read at (use latest if Revision::zero()).
    pub async fn read(
        &self,
        vault: i64,
        key: &RelationshipKey,
        revision: Revision,
    ) -> RepositoryResult<Vec<Relationship>> {
        // If revision is zero, use current revision
        let query_revision = if revision == Revision::zero() {
            self.get_current_revision(vault).await?
        } else {
            revision
        };

        // If specific subject is provided, do a direct lookup
        if let Some(ref subject) = key.subject {
            let storage_key = Self::relationship_key(vault, &key.resource, &key.relation, subject);
            match self.storage.get(&storage_key).await? {
                Some(data) => {
                    let versioned: VersionedRelationship = serde_json::from_slice(&data)
                        .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                    if versioned.is_visible_at(query_revision) {
                        Ok(vec![versioned.relationship])
                    } else {
                        Ok(vec![])
                    }
                },
                None => Ok(vec![]),
            }
        } else {
            // No specific subject - need to scan all relationships for this resource+relation
            self.list_relationships(
                vault,
                Some(&key.resource),
                Some(&key.relation),
                None,
                query_revision,
            )
            .await
        }
    }

    /// Write relationships and return the new revision.
    ///
    /// Deduplicates relationships that already exist at the current revision.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault to write to.
    /// * `relationships` - The relationships to write.
    ///
    /// # Returns
    ///
    /// The new revision after the write.
    pub async fn write(
        &self,
        vault: i64,
        relationships: Vec<Relationship>,
    ) -> RepositoryResult<Revision> {
        if relationships.is_empty() {
            return self.get_current_revision(vault).await;
        }

        // Verify all relationships have the correct vault ID
        for rel in &relationships {
            if rel.vault != vault {
                return Err(RepositoryError::Validation(format!(
                    "Relationship vault {} does not match requested vault {}",
                    rel.vault, vault
                )));
            }
        }

        // Get current revision and increment
        let new_revision = self.increment_revision(vault).await?;

        // Track seen relationships in this batch for deduplication
        let mut seen_in_batch: HashSet<(String, String, String)> = HashSet::new();

        let timestamp_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;

        for relationship in relationships {
            let batch_key = (
                relationship.resource.clone(),
                relationship.relation.clone(),
                relationship.subject.clone(),
            );

            // Skip duplicates within this batch
            if seen_in_batch.contains(&batch_key) {
                continue;
            }

            let storage_key = Self::relationship_key(
                vault,
                &relationship.resource,
                &relationship.relation,
                &relationship.subject,
            );

            // Check if this relationship already exists and is active
            let is_duplicate = match self.storage.get(&storage_key).await? {
                Some(data) => {
                    let existing: VersionedRelationship = serde_json::from_slice(&data)
                        .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                    existing.deleted_at.is_none()
                },
                None => false,
            };

            if is_duplicate {
                // Skip - relationship already exists
                continue;
            }

            seen_in_batch.insert(batch_key);

            // Create versioned relationship
            let versioned = VersionedRelationship::new(relationship.clone(), new_revision);
            let data = serde_json::to_vec(&versioned)
                .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
            self.storage.set(storage_key, data).await?;

            // Append change event
            let event = ChangeEvent::create(relationship, new_revision, timestamp_nanos);
            self.append_change(vault, event).await?;
        }

        Ok(new_revision)
    }

    /// Delete relationships matching the key.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault containing the relationships.
    /// * `key` - The relationship key to match for deletion.
    ///
    /// # Returns
    ///
    /// The new revision after the deletion.
    pub async fn delete(&self, vault: i64, key: &RelationshipKey) -> RepositoryResult<Revision> {
        let new_revision = self.increment_revision(vault).await?;

        let timestamp_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;

        if let Some(ref subject) = key.subject {
            // Delete specific relationship
            let storage_key = Self::relationship_key(vault, &key.resource, &key.relation, subject);
            if let Some(data) = self.storage.get(&storage_key).await? {
                let mut versioned: VersionedRelationship = serde_json::from_slice(&data)
                    .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                if versioned.deleted_at.is_none() {
                    versioned.deleted_at = Some(new_revision);
                    let updated_data = serde_json::to_vec(&versioned)
                        .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                    self.storage.set(storage_key, updated_data).await?;

                    // Append change event
                    let event =
                        ChangeEvent::delete(versioned.relationship, new_revision, timestamp_nanos);
                    self.append_change(vault, event).await?;
                }
            }
        } else {
            // Delete all relationships matching resource+relation
            let relationships = self
                .list_relationships(
                    vault,
                    Some(&key.resource),
                    Some(&key.relation),
                    None,
                    Revision::zero(),
                )
                .await?;

            for relationship in relationships {
                let storage_key = Self::relationship_key(
                    vault,
                    &relationship.resource,
                    &relationship.relation,
                    &relationship.subject,
                );
                if let Some(data) = self.storage.get(&storage_key).await? {
                    let mut versioned: VersionedRelationship = serde_json::from_slice(&data)
                        .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                    if versioned.deleted_at.is_none() {
                        versioned.deleted_at = Some(new_revision);
                        let updated_data = serde_json::to_vec(&versioned)
                            .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                        self.storage.set(storage_key, updated_data).await?;

                        // Append change event
                        let event = ChangeEvent::delete(
                            versioned.relationship,
                            new_revision,
                            timestamp_nanos,
                        );
                        self.append_change(vault, event).await?;
                    }
                }
            }
        }

        Ok(new_revision)
    }

    /// Delete relationships matching a filter.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault containing the relationships.
    /// * `filter` - The filter criteria for deletion.
    /// * `limit` - Optional maximum number of relationships to delete.
    ///
    /// # Returns
    ///
    /// A tuple of (new revision, count of deleted relationships).
    pub async fn delete_by_filter(
        &self,
        vault: i64,
        filter: &DeleteFilter,
        limit: Option<usize>,
    ) -> RepositoryResult<(Revision, usize)> {
        // Validate filter is not empty
        if filter.is_empty() {
            return Err(RepositoryError::Validation(
                "Filter must have at least one field set".to_string(),
            ));
        }

        let new_revision = self.increment_revision(vault).await?;

        let timestamp_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;

        // Find matching relationships
        let relationships = self
            .list_relationships(
                vault,
                filter.resource.as_deref(),
                filter.relation.as_deref(),
                filter.subject.as_deref(),
                Revision::zero(),
            )
            .await?;

        let to_delete: Vec<_> = if let Some(max) = limit {
            relationships.into_iter().take(max).collect()
        } else {
            relationships
        };

        let deleted_count = to_delete.len();

        for relationship in to_delete {
            let storage_key = Self::relationship_key(
                vault,
                &relationship.resource,
                &relationship.relation,
                &relationship.subject,
            );
            if let Some(data) = self.storage.get(&storage_key).await? {
                let mut versioned: VersionedRelationship = serde_json::from_slice(&data)
                    .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                if versioned.deleted_at.is_none() {
                    versioned.deleted_at = Some(new_revision);
                    let updated_data = serde_json::to_vec(&versioned)
                        .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                    self.storage.set(storage_key, updated_data).await?;

                    // Append change event
                    let event =
                        ChangeEvent::delete(versioned.relationship, new_revision, timestamp_nanos);
                    self.append_change(vault, event).await?;
                }
            }
        }

        Ok((new_revision, deleted_count))
    }

    /// Get the current revision for a vault.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault's unique identifier.
    ///
    /// # Returns
    ///
    /// Returns `Revision::zero()` if no writes have occurred.
    pub async fn get_revision(&self, vault: i64) -> RepositoryResult<Revision> {
        self.get_current_revision(vault).await
    }

    /// List relationships with optional filtering.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault to query.
    /// * `resource` - Optional resource filter (e.g., "doc:readme").
    /// * `relation` - Optional relation filter (e.g., "viewer").
    /// * `subject` - Optional subject filter (e.g., "user:alice").
    /// * `revision` - The revision to read at (Revision::zero() for latest).
    pub async fn list_relationships(
        &self,
        vault: i64,
        resource: Option<&str>,
        relation: Option<&str>,
        subject: Option<&str>,
        revision: Revision,
    ) -> RepositoryResult<Vec<Relationship>> {
        // Determine query revision
        let query_revision = if revision == Revision::zero() {
            self.get_current_revision(vault).await?
        } else {
            revision
        };

        // Scan all relationships in the vault
        let start = Self::vault_relationships_prefix(vault);
        let end = Self::vault_relationships_end(vault);

        let entries = self.storage.get_range(start..end).await?;

        let mut results = Vec::new();
        for kv in entries {
            let versioned: VersionedRelationship = match serde_json::from_slice(&kv.value) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Check visibility at query revision
            if !versioned.is_visible_at(query_revision) {
                continue;
            }

            let rel = &versioned.relationship;

            // Apply filters
            if let Some(res) = resource
                && rel.resource != res
            {
                continue;
            }
            if let Some(rel_name) = relation
                && rel.relation != rel_name
            {
                continue;
            }
            if let Some(sub) = subject
                && rel.subject != sub
            {
                continue;
            }

            results.push(rel.clone());
        }

        Ok(results)
    }

    /// List all distinct resources of a given type.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault to query.
    /// * `resource_type` - The resource type prefix (e.g., "document").
    /// * `revision` - The revision to read at.
    ///
    /// # Returns
    ///
    /// Unique resource identifiers like `["document:1", "document:2"]`.
    pub async fn list_resources_by_type(
        &self,
        vault: i64,
        resource_type: &str,
        revision: Revision,
    ) -> RepositoryResult<Vec<String>> {
        let query_revision = if revision == Revision::zero() {
            self.get_current_revision(vault).await?
        } else {
            revision
        };

        let prefix = format!("{}:", resource_type);

        let start = Self::vault_relationships_prefix(vault);
        let end = Self::vault_relationships_end(vault);

        let entries = self.storage.get_range(start..end).await?;

        let mut resources = HashSet::new();
        for kv in entries {
            let versioned: VersionedRelationship = match serde_json::from_slice(&kv.value) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if !versioned.is_visible_at(query_revision) {
                continue;
            }

            if versioned.relationship.resource.starts_with(&prefix) {
                resources.insert(versioned.relationship.resource.clone());
            }
        }

        let mut result: Vec<_> = resources.into_iter().collect();
        result.sort();
        Ok(result)
    }

    /// Append a change event to the change log.
    ///
    /// This is called automatically by write/delete operations.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault to append to.
    /// * `event` - The change event to record.
    pub async fn append_change(&self, vault: i64, event: ChangeEvent) -> RepositoryResult<()> {
        // Create a unique ID from the relationship key to allow multiple events per revision
        let unique_id = format!(
            "{}:{}:{}",
            event.relationship.resource, event.relationship.relation, event.relationship.subject
        );
        let key = keys::changelog::entry_with_id(vault, event.revision, &unique_id);
        let data = serde_json::to_vec(&event)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
        self.storage.set(key, data).await?;
        Ok(())
    }

    /// Read change events from the change log.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault to read from.
    /// * `start_revision` - Start reading from this revision (inclusive).
    /// * `resource_types` - Filter by resource types (empty means all).
    /// * `limit` - Optional maximum number of events to return.
    ///
    /// # Returns
    ///
    /// Events in ascending revision order.
    pub async fn read_changes(
        &self,
        vault: i64,
        start_revision: Revision,
        resource_types: &[String],
        limit: Option<usize>,
    ) -> RepositoryResult<Vec<ChangeEvent>> {
        let start = keys::changelog::from_revision(vault, start_revision);
        let end = keys::changelog::vault_end(vault);

        let entries = self.storage.get_range(start..end).await?;

        let mut events = Vec::new();
        for kv in entries {
            let event: ChangeEvent = match serde_json::from_slice(&kv.value) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Filter by resource types if specified
            if !resource_types.is_empty()
                && let Some(res_type) = event.resource_type()
                && !resource_types.contains(&res_type.to_string())
            {
                continue;
            }

            events.push(event);

            if let Some(max) = limit
                && events.len() >= max
            {
                break;
            }
        }

        Ok(events)
    }

    /// Get the latest change log revision for a vault.
    ///
    /// # Returns
    ///
    /// Returns `Revision::zero()` if no changes exist.
    pub async fn get_change_log_revision(&self, vault: i64) -> RepositoryResult<Revision> {
        let start = keys::changelog::vault_prefix(vault);
        let end = keys::changelog::vault_end(vault);

        let entries = self.storage.get_range(start..end).await?;

        let mut max_revision = Revision::zero();
        for kv in entries {
            if let Ok(event) = serde_json::from_slice::<ChangeEvent>(&kv.value)
                && event.revision > max_revision
            {
                max_revision = event.revision;
            }
        }

        Ok(max_revision)
    }

    /// Access the underlying storage backend.
    ///
    /// This is primarily useful for advanced operations or testing.
    #[inline]
    pub fn storage(&self) -> &S {
        &self.storage
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use inferadb_common_storage::MemoryBackend;
    use inferadb_engine_types::{
        ChangeOperation, DeleteFilter, Relationship, RelationshipKey, Revision,
    };

    use super::*;

    /// Helper to create a test relationship.
    fn test_rel(vault: i64, resource: &str, relation: &str, subject: &str) -> Relationship {
        Relationship {
            vault,
            resource: resource.to_string(),
            relation: relation.to_string(),
            subject: subject.to_string(),
        }
    }

    /// Helper to create a repository with an in-memory backend.
    fn create_repo() -> RelationshipRepository<MemoryBackend> {
        RelationshipRepository::new(MemoryBackend::new())
    }

    const VAULT_ID: i64 = 12345;

    // =========================================================================
    // READ TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_read_returns_empty_for_nonexistent() {
        let repo = create_repo();
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };

        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_read_returns_written_relationship() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };

        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], rel);
    }

    #[tokio::test]
    async fn test_read_with_no_subject_returns_all_subjects() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:bob");
        repo.write(VAULT_ID, vec![rel1.clone(), rel2.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };

        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();

        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_read_respects_revision() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rev = repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };

        // Reading at a revision before write should return empty
        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();
        assert_eq!(result.len(), 1); // zero means "latest"

        // Reading at the write revision should return the relationship
        let result = repo.read(VAULT_ID, &key, rev).await.unwrap();
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_read_does_not_return_deleted_relationship() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };

        // Delete the relationship
        repo.delete(VAULT_ID, &key).await.unwrap();

        // Should not return deleted relationship
        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();
        assert!(result.is_empty());
    }

    // =========================================================================
    // WRITE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_write_returns_new_revision() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");

        let rev = repo.write(VAULT_ID, vec![rel]).await.unwrap();

        assert_eq!(rev, Revision(1));
    }

    #[tokio::test]
    async fn test_write_increments_revision() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:bob");

        let rev1 = repo.write(VAULT_ID, vec![rel1]).await.unwrap();
        let rev2 = repo.write(VAULT_ID, vec![rel2]).await.unwrap();

        assert_eq!(rev1, Revision(1));
        assert_eq!(rev2, Revision(2));
    }

    #[tokio::test]
    async fn test_write_deduplicates_within_batch() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");

        // Write same relationship twice in one batch
        repo.write(VAULT_ID, vec![rel.clone(), rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();

        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_write_deduplicates_existing() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");

        // Write twice
        repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();
        repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();

        // Should only have one relationship
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn test_write_validates_vault_id() {
        let repo = create_repo();
        let rel = test_rel(999, "doc:readme", "viewer", "user:alice"); // Wrong vault

        let result = repo.write(VAULT_ID, vec![rel]).await;

        assert!(matches!(result, Err(RepositoryError::Validation(_))));
    }

    #[tokio::test]
    async fn test_write_empty_batch_returns_current_revision() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel]).await.unwrap();

        let rev = repo.write(VAULT_ID, vec![]).await.unwrap();

        assert_eq!(rev, Revision(1));
    }

    // =========================================================================
    // DELETE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_delete_specific_relationship() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        repo.delete(VAULT_ID, &key).await.unwrap();

        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_delete_all_by_resource_relation() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:bob");
        repo.write(VAULT_ID, vec![rel1, rel2]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        repo.delete(VAULT_ID, &key).await.unwrap();

        let result = repo.read(VAULT_ID, &key, Revision::zero()).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_delete_returns_new_revision() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        let rev = repo.delete(VAULT_ID, &key).await.unwrap();

        assert_eq!(rev, Revision(2));
    }

    #[tokio::test]
    async fn test_deleted_relationship_visible_at_old_revision() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let write_rev = repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        repo.delete(VAULT_ID, &key).await.unwrap();

        // Should still be visible at the write revision
        let result = repo.read(VAULT_ID, &key, write_rev).await.unwrap();
        assert_eq!(result.len(), 1);
    }

    // =========================================================================
    // DELETE BY FILTER TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_delete_by_filter_resource() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:readme", "editor", "user:bob");
        let rel3 = test_rel(VAULT_ID, "doc:other", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel1, rel2, rel3]).await.unwrap();

        let filter = DeleteFilter {
            resource: Some("doc:readme".to_string()),
            relation: None,
            subject: None,
        };
        let (rev, count) = repo.delete_by_filter(VAULT_ID, &filter, None).await.unwrap();

        assert_eq!(count, 2);
        assert_eq!(rev, Revision(2));

        // Only doc:other should remain
        let remaining =
            repo.list_relationships(VAULT_ID, None, None, None, Revision::zero()).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].resource, "doc:other");
    }

    #[tokio::test]
    async fn test_delete_by_filter_with_limit() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:bob");
        let rel3 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:charlie");
        repo.write(VAULT_ID, vec![rel1, rel2, rel3]).await.unwrap();

        let filter = DeleteFilter {
            resource: Some("doc:readme".to_string()),
            relation: Some("viewer".to_string()),
            subject: None,
        };
        let (_, count) = repo.delete_by_filter(VAULT_ID, &filter, Some(2)).await.unwrap();

        assert_eq!(count, 2);

        // One should remain
        let remaining =
            repo.list_relationships(VAULT_ID, None, None, None, Revision::zero()).await.unwrap();
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_by_filter_empty_filter_fails() {
        let repo = create_repo();
        let filter = DeleteFilter { resource: None, relation: None, subject: None };

        let result = repo.delete_by_filter(VAULT_ID, &filter, None).await;

        assert!(matches!(result, Err(RepositoryError::Validation(_))));
    }

    // =========================================================================
    // GET REVISION TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_get_revision_returns_zero_for_new_vault() {
        let repo = create_repo();

        let rev = repo.get_revision(VAULT_ID).await.unwrap();

        assert_eq!(rev, Revision::zero());
    }

    #[tokio::test]
    async fn test_get_revision_returns_current() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel]).await.unwrap();

        let rev = repo.get_revision(VAULT_ID).await.unwrap();

        assert_eq!(rev, Revision(1));
    }

    // =========================================================================
    // LIST RELATIONSHIPS TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_list_relationships_empty() {
        let repo = create_repo();

        let result =
            repo.list_relationships(VAULT_ID, None, None, None, Revision::zero()).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_list_relationships_all() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:b", "editor", "user:bob");
        repo.write(VAULT_ID, vec![rel1, rel2]).await.unwrap();

        let result =
            repo.list_relationships(VAULT_ID, None, None, None, Revision::zero()).await.unwrap();

        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_list_relationships_by_resource() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:b", "viewer", "user:bob");
        repo.write(VAULT_ID, vec![rel1, rel2]).await.unwrap();

        let result = repo
            .list_relationships(VAULT_ID, Some("doc:a"), None, None, Revision::zero())
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].resource, "doc:a");
    }

    #[tokio::test]
    async fn test_list_relationships_by_relation() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:a", "editor", "user:bob");
        repo.write(VAULT_ID, vec![rel1, rel2]).await.unwrap();

        let result = repo
            .list_relationships(VAULT_ID, None, Some("viewer"), None, Revision::zero())
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].relation, "viewer");
    }

    #[tokio::test]
    async fn test_list_relationships_by_subject() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:b", "viewer", "user:bob");
        repo.write(VAULT_ID, vec![rel1, rel2]).await.unwrap();

        let result = repo
            .list_relationships(VAULT_ID, None, None, Some("user:alice"), Revision::zero())
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].subject, "user:alice");
    }

    // =========================================================================
    // LIST RESOURCES BY TYPE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_list_resources_by_type_empty() {
        let repo = create_repo();

        let result = repo.list_resources_by_type(VAULT_ID, "doc", Revision::zero()).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_list_resources_by_type_returns_unique() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:readme", "editor", "user:bob");
        let rel3 = test_rel(VAULT_ID, "doc:other", "viewer", "user:alice");
        let rel4 = test_rel(VAULT_ID, "folder:root", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel1, rel2, rel3, rel4]).await.unwrap();

        let result = repo.list_resources_by_type(VAULT_ID, "doc", Revision::zero()).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"doc:other".to_string()));
        assert!(result.contains(&"doc:readme".to_string()));
    }

    #[tokio::test]
    async fn test_list_resources_by_type_sorted() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:z", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        let rel3 = test_rel(VAULT_ID, "doc:m", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel1, rel2, rel3]).await.unwrap();

        let result = repo.list_resources_by_type(VAULT_ID, "doc", Revision::zero()).await.unwrap();

        assert_eq!(result, vec!["doc:a", "doc:m", "doc:z"]);
    }

    // =========================================================================
    // CHANGE LOG TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_write_appends_create_events() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let events = repo.read_changes(VAULT_ID, Revision::zero(), &[], None).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, ChangeOperation::Create);
        assert_eq!(events[0].relationship, rel);
    }

    #[tokio::test]
    async fn test_delete_appends_delete_events() {
        let repo = create_repo();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        repo.delete(VAULT_ID, &key).await.unwrap();

        let events = repo.read_changes(VAULT_ID, Revision(2), &[], None).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, ChangeOperation::Delete);
    }

    #[tokio::test]
    async fn test_read_changes_filters_by_resource_type() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "folder:root", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel1, rel2]).await.unwrap();

        let events = repo
            .read_changes(VAULT_ID, Revision::zero(), &["doc".to_string()], None)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        assert!(events[0].relationship.resource.starts_with("doc:"));
    }

    #[tokio::test]
    async fn test_read_changes_respects_limit() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:b", "viewer", "user:alice");
        let rel3 = test_rel(VAULT_ID, "doc:c", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel1, rel2, rel3]).await.unwrap();

        let events = repo.read_changes(VAULT_ID, Revision::zero(), &[], Some(2)).await.unwrap();

        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn test_get_change_log_revision_zero_for_empty() {
        let repo = create_repo();

        let rev = repo.get_change_log_revision(VAULT_ID).await.unwrap();

        assert_eq!(rev, Revision::zero());
    }

    #[tokio::test]
    async fn test_get_change_log_revision_returns_latest() {
        let repo = create_repo();
        let rel1 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel1]).await.unwrap();
        let rel2 = test_rel(VAULT_ID, "doc:b", "viewer", "user:alice");
        repo.write(VAULT_ID, vec![rel2]).await.unwrap();

        let rev = repo.get_change_log_revision(VAULT_ID).await.unwrap();

        assert_eq!(rev, Revision(2));
    }

    // =========================================================================
    // VAULT ISOLATION TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_vault_isolation() {
        let repo = create_repo();
        let vault1 = 111;
        let vault2 = 222;

        let rel1 = test_rel(vault1, "doc:readme", "viewer", "user:alice");
        let rel2 = test_rel(vault2, "doc:readme", "viewer", "user:bob");
        repo.write(vault1, vec![rel1]).await.unwrap();
        repo.write(vault2, vec![rel2]).await.unwrap();

        let vault1_rels =
            repo.list_relationships(vault1, None, None, None, Revision::zero()).await.unwrap();
        let vault2_rels =
            repo.list_relationships(vault2, None, None, None, Revision::zero()).await.unwrap();

        assert_eq!(vault1_rels.len(), 1);
        assert_eq!(vault1_rels[0].subject, "user:alice");

        assert_eq!(vault2_rels.len(), 1);
        assert_eq!(vault2_rels[0].subject, "user:bob");
    }
}
