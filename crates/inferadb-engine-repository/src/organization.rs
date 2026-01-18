//! Repository for Organization entity operations.
//!
//! This module provides [`OrganizationRepository`] which handles CRUD operations
//! for organizations using a generic [`StorageBackend`].
//!
//! # Key Schema
//!
//! - `engine:org:{id}` → JSON-serialized `Organization`
//! - `engine:org:list:{id}` → `id` bytes (for listing)

use inferadb_engine_types::organization::Organization;
use inferadb_storage::StorageBackend;

use crate::{
    error::{RepositoryError, RepositoryResult},
    keys,
};

/// Repository for Organization entity operations.
///
/// Provides CRUD operations for organizations using a generic storage backend.
/// All operations are async and return [`RepositoryResult`].
///
/// # Type Parameters
///
/// * `S` - A type implementing [`StorageBackend`] for underlying storage operations.
///
/// # Example
///
/// ```ignore
/// use inferadb_storage::MemoryBackend;
/// use inferadb_engine_repository::OrganizationRepository;
///
/// let storage = MemoryBackend::new();
/// let repo = OrganizationRepository::new(storage);
/// ```
pub struct OrganizationRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> OrganizationRepository<S> {
    /// Create a new organization repository with the given storage backend.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Create a new organization.
    ///
    /// # Arguments
    ///
    /// * `org` - The organization to create.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` if an organization with the same ID exists.
    /// Returns an error if the storage operation fails.
    pub async fn create(&self, org: Organization) -> RepositoryResult<Organization> {
        // Check if organization already exists
        let org_key = keys::organization::by_id(org.id);
        if self.storage.get(&org_key).await?.is_some() {
            return Err(RepositoryError::AlreadyExists(format!(
                "Organization {} already exists",
                org.id
            )));
        }

        // Serialize organization
        let org_data =
            serde_json::to_vec(&org).map_err(|e| RepositoryError::Serialization(e.to_string()))?;

        // Use transaction for atomicity: store org + list index
        let mut txn = self.storage.transaction().await?;

        // Store organization record
        txn.set(org_key, org_data);

        // Store list index entry (value is the ID as bytes for efficient scanning)
        let list_key = keys::organization::list_entry(org.id);
        txn.set(list_key, org.id.to_le_bytes().to_vec());

        txn.commit().await?;

        Ok(org)
    }

    /// Get an organization by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The organization's unique identifier.
    ///
    /// # Returns
    ///
    /// Returns `None` if the organization does not exist.
    pub async fn get(&self, id: i64) -> RepositoryResult<Option<Organization>> {
        let key = keys::organization::by_id(id);
        match self.storage.get(&key).await? {
            Some(data) => {
                let org: Organization = serde_json::from_slice(&data)
                    .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                Ok(Some(org))
            },
            None => Ok(None),
        }
    }

    /// List all organizations up to an optional limit.
    ///
    /// # Arguments
    ///
    /// * `limit` - Optional maximum number of organizations to return.
    pub async fn list(&self, limit: Option<usize>) -> RepositoryResult<Vec<Organization>> {
        let start = keys::organization::list_prefix();
        let end = keys::organization::list_end();

        let entries = self.storage.get_range(start..end).await?;

        let mut orgs = Vec::new();
        for kv in entries {
            // The value contains the organization ID as little-endian bytes
            if kv.value.len() != 8 {
                continue;
            }
            let id = i64::from_le_bytes(kv.value[0..8].try_into().unwrap());

            if let Some(org) = self.get(id).await? {
                orgs.push(org);

                // Respect limit if provided
                if let Some(max) = limit {
                    if orgs.len() >= max {
                        break;
                    }
                }
            }
        }

        Ok(orgs)
    }

    /// Update an existing organization.
    ///
    /// # Arguments
    ///
    /// * `org` - The organization with updated fields.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the organization does not exist.
    pub async fn update(&self, org: Organization) -> RepositoryResult<Organization> {
        // Check if organization exists
        let org_key = keys::organization::by_id(org.id);
        if self.storage.get(&org_key).await?.is_none() {
            return Err(RepositoryError::NotFound(format!("Organization {} not found", org.id)));
        }

        // Serialize and update
        let org_data =
            serde_json::to_vec(&org).map_err(|e| RepositoryError::Serialization(e.to_string()))?;

        self.storage.set(org_key, org_data).await?;

        Ok(org)
    }

    /// Delete an organization by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The organization's unique identifier.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the organization does not exist.
    pub async fn delete(&self, id: i64) -> RepositoryResult<()> {
        // Check if organization exists
        let org_key = keys::organization::by_id(id);
        if self.storage.get(&org_key).await?.is_none() {
            return Err(RepositoryError::NotFound(format!("Organization {} not found", id)));
        }

        // Use transaction for atomicity: delete org + list index
        let mut txn = self.storage.transaction().await?;

        txn.delete(org_key);
        txn.delete(keys::organization::list_entry(id));

        txn.commit().await?;

        Ok(())
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
mod tests {
    use chrono::Utc;
    use inferadb_engine_types::organization::Organization;
    use inferadb_storage::MemoryBackend;

    use super::*;

    /// Helper to create a test organization with the given ID and name.
    fn test_org(id: i64, name: &str) -> Organization {
        Organization { id, name: name.to_string(), created_at: Utc::now(), updated_at: Utc::now() }
    }

    /// Helper to create a repository with an in-memory backend.
    fn create_repo() -> OrganizationRepository<MemoryBackend> {
        OrganizationRepository::new(MemoryBackend::new())
    }

    // =========================================================================
    // CREATE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_create_returns_the_organization() {
        let repo = create_repo();
        let org = test_org(100, "Acme Corp");

        let result = repo.create(org.clone()).await.unwrap();

        assert_eq!(result.id, 100);
        assert_eq!(result.name, "Acme Corp");
    }

    #[tokio::test]
    async fn test_create_persists_organization() {
        let repo = create_repo();
        let org = test_org(100, "Acme Corp");

        repo.create(org).await.unwrap();

        // Verify it was persisted
        let retrieved = repo.get(100).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Acme Corp");
    }

    #[tokio::test]
    async fn test_create_rejects_duplicate_id() {
        let repo = create_repo();
        let org1 = test_org(100, "Acme Corp");
        let org2 = test_org(100, "Other Corp");

        repo.create(org1).await.unwrap();
        let result = repo.create(org2).await;

        assert!(matches!(result, Err(RepositoryError::AlreadyExists(_))));
    }

    // =========================================================================
    // GET TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_get_returns_none_for_nonexistent() {
        let repo = create_repo();

        let result = repo.get(999).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_returns_organization() {
        let repo = create_repo();
        let org = test_org(100, "Acme Corp");
        repo.create(org).await.unwrap();

        let result = repo.get(100).await.unwrap();

        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.id, 100);
        assert_eq!(retrieved.name, "Acme Corp");
    }

    // =========================================================================
    // LIST TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_list_returns_empty_when_no_orgs() {
        let repo = create_repo();

        let result = repo.list(None).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_list_returns_all_orgs() {
        let repo = create_repo();
        repo.create(test_org(100, "Org A")).await.unwrap();
        repo.create(test_org(101, "Org B")).await.unwrap();
        repo.create(test_org(102, "Org C")).await.unwrap();

        let result = repo.list(None).await.unwrap();

        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_list_respects_limit() {
        let repo = create_repo();
        repo.create(test_org(100, "Org A")).await.unwrap();
        repo.create(test_org(101, "Org B")).await.unwrap();
        repo.create(test_org(102, "Org C")).await.unwrap();

        let result = repo.list(Some(2)).await.unwrap();

        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_list_limit_larger_than_count() {
        let repo = create_repo();
        repo.create(test_org(100, "Org A")).await.unwrap();

        let result = repo.list(Some(100)).await.unwrap();

        assert_eq!(result.len(), 1);
    }

    // =========================================================================
    // UPDATE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_update_returns_updated_organization() {
        let repo = create_repo();
        let org = test_org(100, "Old Name");
        repo.create(org).await.unwrap();

        let mut updated = test_org(100, "New Name");
        updated.updated_at = Utc::now();

        let result = repo.update(updated.clone()).await.unwrap();

        assert_eq!(result.id, 100);
        assert_eq!(result.name, "New Name");
    }

    #[tokio::test]
    async fn test_update_persists_changes() {
        let repo = create_repo();
        let org = test_org(100, "Old Name");
        repo.create(org).await.unwrap();

        let updated = test_org(100, "New Name");
        repo.update(updated).await.unwrap();

        let retrieved = repo.get(100).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "New Name");
    }

    #[tokio::test]
    async fn test_update_fails_for_nonexistent() {
        let repo = create_repo();
        let org = test_org(999, "Ghost Org");

        let result = repo.update(org).await;

        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    // =========================================================================
    // DELETE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_delete_removes_organization() {
        let repo = create_repo();
        let org = test_org(100, "Acme Corp");
        repo.create(org).await.unwrap();

        repo.delete(100).await.unwrap();

        let result = repo.get(100).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_removes_from_list_index() {
        let repo = create_repo();
        repo.create(test_org(100, "Org A")).await.unwrap();
        repo.create(test_org(101, "Org B")).await.unwrap();

        repo.delete(100).await.unwrap();

        let list = repo.list(None).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, 101);
    }

    #[tokio::test]
    async fn test_delete_fails_for_nonexistent() {
        let repo = create_repo();

        let result = repo.delete(999).await;

        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    // =========================================================================
    // TRANSACTION / ATOMICITY TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_create_is_atomic() {
        // If create fails partially, neither the org nor list index should exist
        let repo = create_repo();
        let org = test_org(100, "Acme Corp");
        repo.create(org).await.unwrap();

        // Try to create duplicate - should fail
        let org2 = test_org(100, "Duplicate");
        let _ = repo.create(org2).await;

        // Original org should still exist unchanged
        let retrieved = repo.get(100).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Acme Corp");

        // List should have exactly one entry
        let list = repo.list(None).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_is_atomic() {
        let repo = create_repo();
        repo.create(test_org(100, "Org A")).await.unwrap();
        repo.create(test_org(101, "Org B")).await.unwrap();

        // Delete one
        repo.delete(100).await.unwrap();

        // The other should still be intact
        let org_b = repo.get(101).await.unwrap();
        assert!(org_b.is_some());

        let list = repo.list(None).await.unwrap();
        assert_eq!(list.len(), 1);
    }
}
