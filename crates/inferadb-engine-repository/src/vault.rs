//! Repository for Vault entity operations.
//!
//! This module provides [`VaultRepository`] which handles CRUD operations
//! for vaults and system configuration using a generic [`StorageBackend`].
//!
//! # Key Schema
//!
//! - `engine:vault:{id}` → JSON-serialized `Vault`
//! - `engine:vault:org:{org_id}:{vault_id}` → `vault_id` bytes (for org listing)
//! - `engine:system_config` → JSON-serialized `SystemConfig`

use inferadb_engine_types::vault::Vault;
use inferadb_storage::StorageBackend;

use crate::{
    error::{RepositoryError, RepositoryResult},
    keys,
};

/// System-wide configuration stored in the Engine.
///
/// This structure holds global configuration settings that apply
/// across all organizations and vaults.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemConfig {
    /// Whether the system has been initialized.
    pub initialized: bool,

    /// The schema version for data migrations.
    pub schema_version: u32,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self { initialized: false, schema_version: 1 }
    }
}

/// Repository for Vault entity operations.
///
/// Provides CRUD operations for vaults and system configuration
/// using a generic storage backend.
///
/// # Type Parameters
///
/// * `S` - A type implementing [`StorageBackend`] for underlying storage operations.
///
/// # Example
///
/// ```ignore
/// use inferadb_storage::MemoryBackend;
/// use inferadb_engine_repository::VaultRepository;
///
/// let storage = MemoryBackend::new();
/// let repo = VaultRepository::new(storage);
/// ```
pub struct VaultRepository<S: StorageBackend> {
    storage: S,
}

impl<S: StorageBackend> VaultRepository<S> {
    /// Create a new vault repository with the given storage backend.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Create a new vault.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault to create.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` if a vault with the same ID exists.
    /// Returns an error if the storage operation fails.
    pub async fn create(&self, vault: Vault) -> RepositoryResult<Vault> {
        // Check if vault already exists
        let vault_key = keys::vault::by_id(vault.id);
        if self.storage.get(&vault_key).await?.is_some() {
            return Err(RepositoryError::AlreadyExists(format!(
                "Vault {} already exists",
                vault.id
            )));
        }

        // Serialize vault
        let vault_data = serde_json::to_vec(&vault)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

        // Use transaction for atomicity: store vault + org index
        let mut txn = self.storage.transaction().await?;

        // Store vault record
        txn.set(vault_key, vault_data);

        // Store organization index entry (value is the vault ID as bytes)
        let org_index_key = keys::vault::org_index(vault.organization, vault.id);
        txn.set(org_index_key, vault.id.to_le_bytes().to_vec());

        txn.commit().await?;

        Ok(vault)
    }

    /// Get a vault by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The vault's unique identifier.
    ///
    /// # Returns
    ///
    /// Returns `None` if the vault does not exist.
    pub async fn get(&self, id: i64) -> RepositoryResult<Option<Vault>> {
        let key = keys::vault::by_id(id);
        match self.storage.get(&key).await? {
            Some(data) => {
                let vault: Vault = serde_json::from_slice(&data)
                    .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                Ok(Some(vault))
            },
            None => Ok(None),
        }
    }

    /// List all vaults belonging to an organization.
    ///
    /// # Arguments
    ///
    /// * `org_id` - The organization's unique identifier.
    pub async fn list_by_organization(&self, org_id: i64) -> RepositoryResult<Vec<Vault>> {
        let start = keys::vault::org_prefix(org_id);
        let end = keys::vault::org_end(org_id);

        let entries = self.storage.get_range(start..end).await?;

        let mut vaults = Vec::new();
        for kv in entries {
            // The value contains the vault ID as little-endian bytes
            let Ok(bytes): Result<[u8; 8], _> = kv.value[..].try_into() else {
                continue;
            };
            let vault_id = i64::from_le_bytes(bytes);

            if let Some(vault) = self.get(vault_id).await? {
                vaults.push(vault);
            }
        }

        Ok(vaults)
    }

    /// Update an existing vault.
    ///
    /// # Arguments
    ///
    /// * `vault` - The vault with updated fields.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the vault does not exist.
    pub async fn update(&self, vault: Vault) -> RepositoryResult<Vault> {
        // Check if vault exists
        let vault_key = keys::vault::by_id(vault.id);
        if self.storage.get(&vault_key).await?.is_none() {
            return Err(RepositoryError::NotFound(format!("Vault {} not found", vault.id)));
        }

        // Serialize and update
        let vault_data = serde_json::to_vec(&vault)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

        self.storage.set(vault_key, vault_data).await?;

        Ok(vault)
    }

    /// Delete a vault by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The vault's unique identifier.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the vault does not exist.
    pub async fn delete(&self, id: i64) -> RepositoryResult<()> {
        // Check if vault exists and get its org for index cleanup
        let vault_key = keys::vault::by_id(id);
        let vault = match self.storage.get(&vault_key).await? {
            Some(data) => {
                let v: Vault = serde_json::from_slice(&data)
                    .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                v
            },
            None => {
                return Err(RepositoryError::NotFound(format!("Vault {} not found", id)));
            },
        };

        // Use transaction for atomicity: delete vault + org index
        let mut txn = self.storage.transaction().await?;

        txn.delete(vault_key);
        txn.delete(keys::vault::org_index(vault.organization, id));

        txn.commit().await?;

        Ok(())
    }

    /// Get the system configuration.
    ///
    /// # Returns
    ///
    /// Returns `None` if no configuration has been set.
    pub async fn get_system_config(&self) -> RepositoryResult<Option<SystemConfig>> {
        let key = keys::system::config();
        match self.storage.get(&key).await? {
            Some(data) => {
                let config: SystemConfig = serde_json::from_slice(&data)
                    .map_err(|e| RepositoryError::Serialization(e.to_string()))?;
                Ok(Some(config))
            },
            None => Ok(None),
        }
    }

    /// Set the system configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration to store.
    pub async fn set_system_config(&self, config: SystemConfig) -> RepositoryResult<()> {
        let key = keys::system::config();
        let data = serde_json::to_vec(&config)
            .map_err(|e| RepositoryError::Serialization(e.to_string()))?;

        self.storage.set(key, data).await?;

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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use chrono::Utc;
    use inferadb_engine_types::vault::Vault;
    use inferadb_storage::MemoryBackend;

    use super::*;

    /// Helper to create a test vault with the given ID, org, and name.
    fn test_vault(id: i64, organization: i64, name: &str) -> Vault {
        Vault {
            id,
            organization,
            name: name.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Helper to create a repository with an in-memory backend.
    fn create_repo() -> VaultRepository<MemoryBackend> {
        VaultRepository::new(MemoryBackend::new())
    }

    // =========================================================================
    // CREATE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_create_returns_the_vault() {
        let repo = create_repo();
        let vault = test_vault(100, 1, "Production");

        let result = repo.create(vault.clone()).await.unwrap();

        assert_eq!(result.id, 100);
        assert_eq!(result.organization, 1);
        assert_eq!(result.name, "Production");
    }

    #[tokio::test]
    async fn test_create_persists_vault() {
        let repo = create_repo();
        let vault = test_vault(100, 1, "Production");

        repo.create(vault).await.unwrap();

        // Verify it was persisted
        let retrieved = repo.get(100).await.unwrap();
        assert!(retrieved.is_some());
        let v = retrieved.unwrap();
        assert_eq!(v.name, "Production");
        assert_eq!(v.organization, 1);
    }

    #[tokio::test]
    async fn test_create_rejects_duplicate_id() {
        let repo = create_repo();
        let vault1 = test_vault(100, 1, "Vault A");
        let vault2 = test_vault(100, 2, "Vault B");

        repo.create(vault1).await.unwrap();
        let result = repo.create(vault2).await;

        assert!(matches!(result, Err(RepositoryError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_create_allows_same_name_different_org() {
        let repo = create_repo();
        let vault1 = test_vault(100, 1, "Production");
        let vault2 = test_vault(101, 2, "Production");

        repo.create(vault1).await.unwrap();
        let result = repo.create(vault2).await;

        assert!(result.is_ok());
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
    async fn test_get_returns_vault() {
        let repo = create_repo();
        let vault = test_vault(100, 1, "Production");
        repo.create(vault).await.unwrap();

        let result = repo.get(100).await.unwrap();

        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.id, 100);
        assert_eq!(retrieved.organization, 1);
        assert_eq!(retrieved.name, "Production");
    }

    // =========================================================================
    // LIST BY ORGANIZATION TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_list_by_organization_returns_empty_when_no_vaults() {
        let repo = create_repo();

        let result = repo.list_by_organization(1).await.unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_list_by_organization_returns_only_matching_org() {
        let repo = create_repo();
        repo.create(test_vault(100, 1, "Org1 Vault A")).await.unwrap();
        repo.create(test_vault(101, 1, "Org1 Vault B")).await.unwrap();
        repo.create(test_vault(200, 2, "Org2 Vault")).await.unwrap();

        let result = repo.list_by_organization(1).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|v| v.organization == 1));
    }

    #[tokio::test]
    async fn test_list_by_organization_returns_all_vaults_for_org() {
        let repo = create_repo();
        repo.create(test_vault(100, 1, "Vault A")).await.unwrap();
        repo.create(test_vault(101, 1, "Vault B")).await.unwrap();
        repo.create(test_vault(102, 1, "Vault C")).await.unwrap();

        let result = repo.list_by_organization(1).await.unwrap();

        assert_eq!(result.len(), 3);
    }

    // =========================================================================
    // UPDATE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_update_returns_updated_vault() {
        let repo = create_repo();
        let vault = test_vault(100, 1, "Old Name");
        repo.create(vault).await.unwrap();

        let updated = test_vault(100, 1, "New Name");
        let result = repo.update(updated).await.unwrap();

        assert_eq!(result.id, 100);
        assert_eq!(result.name, "New Name");
    }

    #[tokio::test]
    async fn test_update_persists_changes() {
        let repo = create_repo();
        let vault = test_vault(100, 1, "Old Name");
        repo.create(vault).await.unwrap();

        let updated = test_vault(100, 1, "New Name");
        repo.update(updated).await.unwrap();

        let retrieved = repo.get(100).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "New Name");
    }

    #[tokio::test]
    async fn test_update_fails_for_nonexistent() {
        let repo = create_repo();
        let vault = test_vault(999, 1, "Ghost Vault");

        let result = repo.update(vault).await;

        assert!(matches!(result, Err(RepositoryError::NotFound(_))));
    }

    // =========================================================================
    // DELETE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_delete_removes_vault() {
        let repo = create_repo();
        let vault = test_vault(100, 1, "Production");
        repo.create(vault).await.unwrap();

        repo.delete(100).await.unwrap();

        let result = repo.get(100).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_removes_from_org_index() {
        let repo = create_repo();
        repo.create(test_vault(100, 1, "Vault A")).await.unwrap();
        repo.create(test_vault(101, 1, "Vault B")).await.unwrap();

        repo.delete(100).await.unwrap();

        let list = repo.list_by_organization(1).await.unwrap();
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
    // SYSTEM CONFIG TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_get_system_config_returns_none_when_not_set() {
        let repo = create_repo();

        let result = repo.get_system_config().await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_set_system_config_persists() {
        let repo = create_repo();
        let config = SystemConfig { initialized: true, schema_version: 2 };

        repo.set_system_config(config).await.unwrap();

        let result = repo.get_system_config().await.unwrap();
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert!(retrieved.initialized);
        assert_eq!(retrieved.schema_version, 2);
    }

    #[tokio::test]
    async fn test_set_system_config_overwrites() {
        let repo = create_repo();
        let config1 = SystemConfig { initialized: false, schema_version: 1 };
        let config2 = SystemConfig { initialized: true, schema_version: 3 };

        repo.set_system_config(config1).await.unwrap();
        repo.set_system_config(config2).await.unwrap();

        let result = repo.get_system_config().await.unwrap().unwrap();
        assert!(result.initialized);
        assert_eq!(result.schema_version, 3);
    }

    // =========================================================================
    // TRANSACTION / ATOMICITY TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_create_is_atomic() {
        let repo = create_repo();
        let vault = test_vault(100, 1, "Production");
        repo.create(vault).await.unwrap();

        // Try to create duplicate - should fail
        let vault2 = test_vault(100, 1, "Duplicate");
        let _ = repo.create(vault2).await;

        // Original vault should still exist unchanged
        let retrieved = repo.get(100).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Production");

        // Org index should have exactly one entry
        let list = repo.list_by_organization(1).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_is_atomic() {
        let repo = create_repo();
        repo.create(test_vault(100, 1, "Vault A")).await.unwrap();
        repo.create(test_vault(101, 1, "Vault B")).await.unwrap();

        // Delete one
        repo.delete(100).await.unwrap();

        // The other should still be intact
        let vault_b = repo.get(101).await.unwrap();
        assert!(vault_b.is_some());

        let list = repo.list_by_organization(1).await.unwrap();
        assert_eq!(list.len(), 1);
    }
}
