//! Unified storage facade for Engine operations.
//!
//! This module provides [`EngineStorage`] which combines all repositories
//! and exposes a unified interface for the API layer.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                EngineStorage<S>                 │
//! │    (Unified facade for all storage operations)  │
//! ├─────────┬───────────────┬───────────────────────┤
//! │ RelRepo │    OrgRepo    │      VaultRepo        │
//! │         │               │                       │
//! └─────────┴───────────────┴───────────────────────┘
//!                      │
//!                      ▼
//!              StorageBackend (S)
//! ```

use inferadb_engine_types::{
    ChangeEvent, DeleteFilter, Organization, Relationship, RelationshipKey, Revision, StoreError,
    StoreResult, SystemConfig, Vault,
};
use inferadb_storage::StorageBackend;

use crate::{
    OrganizationRepository, RelationshipRepository, RepositoryError, RepositoryResult,
    VaultRepository,
};

/// Convert a repository error to a store error.
fn to_store_error(err: RepositoryError) -> StoreError {
    match err {
        RepositoryError::NotFound(_) => StoreError::NotFound,
        RepositoryError::AlreadyExists(_) => StoreError::Conflict,
        RepositoryError::Conflict => StoreError::Conflict,
        RepositoryError::Serialization(msg) => StoreError::Internal(msg),
        RepositoryError::Validation(msg) => StoreError::Internal(msg),
        RepositoryError::Connection(msg) => StoreError::Database(msg),
        RepositoryError::Timeout => StoreError::Database("Timeout".to_string()),
        RepositoryError::Internal(msg) => StoreError::Internal(msg),
    }
}

/// Convert a repository result to a store result.
fn to_store_result<T>(result: RepositoryResult<T>) -> StoreResult<T> {
    result.map_err(to_store_error)
}

/// Unified storage facade combining all Engine repositories.
///
/// This struct provides a single point of access to all storage operations,
/// delegating to the appropriate repository based on the operation type.
///
/// # Type Parameters
///
/// * `S` - A type implementing [`StorageBackend`] for underlying storage operations.
///
/// # Example
///
/// ```ignore
/// use inferadb_storage::MemoryBackend;
/// use inferadb_engine_repository::EngineStorage;
///
/// let storage = EngineStorage::builder().backend(MemoryBackend::new()).build();
///
/// // Use for relationship operations
/// let rev = storage.write_relationships(vault_id, relationships).await?;
///
/// // Use for organization operations
/// let org = storage.create_organization(org).await?;
/// ```
pub struct EngineStorage<S: StorageBackend> {
    relationships: RelationshipRepository<S>,
    organizations: OrganizationRepository<S>,
    vaults: VaultRepository<S>,
}

#[bon::bon]
impl<S: StorageBackend + Clone> EngineStorage<S> {
    /// Create a new engine storage facade with the given backend.
    ///
    /// The backend is cloned for each repository, allowing them to share
    /// the underlying storage while maintaining independent state.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use inferadb_storage::MemoryBackend;
    /// use inferadb_engine_repository::EngineStorage;
    ///
    /// let storage = EngineStorage::builder()
    ///     .backend(MemoryBackend::new())
    ///     .build();
    /// ```
    #[builder]
    pub fn new(backend: S) -> Self {
        Self {
            relationships: RelationshipRepository::new(backend.clone()),
            organizations: OrganizationRepository::new(backend.clone()),
            vaults: VaultRepository::new(backend),
        }
    }
}

impl<S: StorageBackend> EngineStorage<S> {
    // =========================================================================
    // Relationship Operations
    // =========================================================================

    /// Read relationships matching the key at a specific revision.
    pub async fn read_relationships(
        &self,
        vault: i64,
        key: &RelationshipKey,
        revision: Revision,
    ) -> StoreResult<Vec<Relationship>> {
        to_store_result(self.relationships.read(vault, key, revision).await)
    }

    /// Write relationships and return the new revision.
    pub async fn write_relationships(
        &self,
        vault: i64,
        relationships: Vec<Relationship>,
    ) -> StoreResult<Revision> {
        to_store_result(self.relationships.write(vault, relationships).await)
    }

    /// Delete relationships matching the key.
    pub async fn delete_relationships(
        &self,
        vault: i64,
        key: &RelationshipKey,
    ) -> StoreResult<Revision> {
        to_store_result(self.relationships.delete(vault, key).await)
    }

    /// Delete relationships matching a filter.
    pub async fn delete_relationships_by_filter(
        &self,
        vault: i64,
        filter: &DeleteFilter,
        limit: Option<usize>,
    ) -> StoreResult<(Revision, usize)> {
        to_store_result(self.relationships.delete_by_filter(vault, filter, limit).await)
    }

    /// Get the current revision for a vault.
    pub async fn get_revision(&self, vault: i64) -> StoreResult<Revision> {
        to_store_result(self.relationships.get_revision(vault).await)
    }

    /// List relationships with optional filtering.
    pub async fn list_relationships(
        &self,
        vault: i64,
        resource: Option<&str>,
        relation: Option<&str>,
        subject: Option<&str>,
        revision: Revision,
    ) -> StoreResult<Vec<Relationship>> {
        to_store_result(
            self.relationships
                .list_relationships(vault, resource, relation, subject, revision)
                .await,
        )
    }

    /// List all distinct resources of a given type.
    pub async fn list_resources_by_type(
        &self,
        vault: i64,
        resource_type: &str,
        revision: Revision,
    ) -> StoreResult<Vec<String>> {
        to_store_result(
            self.relationships.list_resources_by_type(vault, resource_type, revision).await,
        )
    }

    /// Append a change event to the change log.
    pub async fn append_change(&self, vault: i64, event: ChangeEvent) -> StoreResult<()> {
        to_store_result(self.relationships.append_change(vault, event).await)
    }

    /// Read change events from the change log.
    pub async fn read_changes(
        &self,
        vault: i64,
        start_revision: Revision,
        resource_types: &[String],
        limit: Option<usize>,
    ) -> StoreResult<Vec<ChangeEvent>> {
        to_store_result(
            self.relationships.read_changes(vault, start_revision, resource_types, limit).await,
        )
    }

    /// Get the latest change log revision.
    pub async fn get_change_log_revision(&self, vault: i64) -> StoreResult<Revision> {
        to_store_result(self.relationships.get_change_log_revision(vault).await)
    }

    // =========================================================================
    // Organization Operations
    // =========================================================================

    /// Create a new organization.
    pub async fn create_organization(&self, org: Organization) -> StoreResult<Organization> {
        to_store_result(self.organizations.create(org).await)
    }

    /// Get an organization by ID.
    pub async fn get_organization(&self, id: i64) -> StoreResult<Option<Organization>> {
        to_store_result(self.organizations.get(id).await)
    }

    /// List all organizations up to an optional limit.
    pub async fn list_organizations(&self, limit: Option<usize>) -> StoreResult<Vec<Organization>> {
        to_store_result(self.organizations.list(limit).await)
    }

    /// Update an existing organization.
    pub async fn update_organization(&self, org: Organization) -> StoreResult<Organization> {
        to_store_result(self.organizations.update(org).await)
    }

    /// Delete an organization by ID.
    ///
    /// This performs a cascade delete, removing all vaults owned by the
    /// organization before deleting the organization itself.
    pub async fn delete_organization(&self, id: i64) -> StoreResult<()> {
        // Find and delete all vaults owned by this organization
        let vaults = to_store_result(self.vaults.list_by_organization(id).await)?;
        for vault in vaults {
            to_store_result(self.vaults.delete(vault.id).await)?;
        }

        // Delete the organization
        to_store_result(self.organizations.delete(id).await)
    }

    // =========================================================================
    // Vault Operations
    // =========================================================================

    /// Create a new vault.
    pub async fn create_vault(&self, vault: Vault) -> StoreResult<Vault> {
        to_store_result(self.vaults.create(vault).await)
    }

    /// Get a vault by ID.
    pub async fn get_vault(&self, id: i64) -> StoreResult<Option<Vault>> {
        to_store_result(self.vaults.get(id).await)
    }

    /// List all vaults for an organization.
    pub async fn list_vaults_for_organization(&self, org_id: i64) -> StoreResult<Vec<Vault>> {
        to_store_result(self.vaults.list_by_organization(org_id).await)
    }

    /// Update an existing vault.
    pub async fn update_vault(&self, vault: Vault) -> StoreResult<Vault> {
        to_store_result(self.vaults.update(vault).await)
    }

    /// Delete a vault by ID.
    pub async fn delete_vault(&self, id: i64) -> StoreResult<()> {
        to_store_result(self.vaults.delete(id).await)
    }

    /// Get the system configuration.
    pub async fn get_system_config(&self) -> StoreResult<Option<SystemConfig>> {
        // Note: We use inferadb_engine_types::SystemConfig here (default_vault,
        // default_organization) which is different from the internal repository
        // SystemConfig. For now, we store/retrieve the types version directly.
        let key = crate::keys::system::config();
        match self.vaults.storage().get(&key).await {
            Ok(Some(data)) => {
                let config: SystemConfig = serde_json::from_slice(&data)
                    .map_err(|e| StoreError::Internal(e.to_string()))?;
                Ok(Some(config))
            },
            Ok(None) => Ok(None),
            Err(e) => Err(to_store_error(e.into())),
        }
    }

    /// Set the system configuration.
    pub async fn set_system_config(&self, config: SystemConfig) -> StoreResult<()> {
        let key = crate::keys::system::config();
        let data = serde_json::to_vec(&config).map_err(|e| StoreError::Internal(e.to_string()))?;
        self.vaults.storage().set(key, data).await.map_err(|e| to_store_error(e.into()))
    }

    // =========================================================================
    // Access to Underlying Components
    // =========================================================================

    /// Access the relationship repository directly.
    #[inline]
    pub fn relationships(&self) -> &RelationshipRepository<S> {
        &self.relationships
    }

    /// Access the organization repository directly.
    #[inline]
    pub fn organizations(&self) -> &OrganizationRepository<S> {
        &self.organizations
    }

    /// Access the vault repository directly.
    #[inline]
    pub fn vaults(&self) -> &VaultRepository<S> {
        &self.vaults
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use chrono::Utc;
    use inferadb_engine_types::{
        ChangeOperation, Organization, Relationship, RelationshipKey, Revision, StoreError,
        SystemConfig, Vault,
    };
    use inferadb_storage::MemoryBackend;

    use super::*;

    /// Helper to create test storage.
    fn create_storage() -> EngineStorage<MemoryBackend> {
        EngineStorage::builder().backend(MemoryBackend::new()).build()
    }

    /// Helper to create a test organization.
    fn test_org(id: i64, name: &str) -> Organization {
        Organization { id, name: name.to_string(), created_at: Utc::now(), updated_at: Utc::now() }
    }

    /// Helper to create a test vault.
    fn test_vault(id: i64, org: i64, name: &str) -> Vault {
        Vault {
            id,
            organization: org,
            name: name.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Helper to create a test relationship.
    fn test_rel(vault: i64, resource: &str, relation: &str, subject: &str) -> Relationship {
        Relationship {
            vault,
            resource: resource.to_string(),
            relation: relation.to_string(),
            subject: subject.to_string(),
        }
    }

    const VAULT_ID: i64 = 12345;
    const ORG_ID: i64 = 1;

    // =========================================================================
    // CONSTRUCTION TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_new_creates_storage_with_all_repositories() {
        let storage = create_storage();

        // Verify all repositories are accessible
        let _ = storage.relationships();
        let _ = storage.organizations();
        let _ = storage.vaults();
    }

    #[tokio::test]
    async fn test_builder_creates_storage() {
        // With bon, we use EngineStorage::builder().backend(...).build()
        let storage = EngineStorage::builder().backend(MemoryBackend::new()).build();

        // Verify storage works
        let rev = storage.get_revision(VAULT_ID).await.unwrap();
        assert_eq!(rev, Revision::zero());
    }

    #[tokio::test]
    async fn test_builder_generic_type_inference() {
        // Verify that generic type is correctly inferred from backend
        let storage: EngineStorage<MemoryBackend> =
            EngineStorage::builder().backend(MemoryBackend::new()).build();

        // Verify all repositories are accessible
        let _ = storage.relationships();
        let _ = storage.organizations();
        let _ = storage.vaults();
    }

    // Note: With bon, missing backend is a compile-time error, not a runtime panic.
    // The following tests were removed because the builder API now enforces
    // required fields at compile time:
    // - test_builder_panics_without_backend (was runtime panic)
    // - test_builder_try_build_returns_none_without_backend (was Option return)

    // =========================================================================
    // RELATIONSHIP OPERATION TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_write_relationships_returns_revision() {
        let storage = create_storage();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");

        let rev = storage.write_relationships(VAULT_ID, vec![rel]).await.unwrap();

        assert_eq!(rev, Revision(1));
    }

    #[tokio::test]
    async fn test_read_relationships_returns_written_data() {
        let storage = create_storage();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        storage.write_relationships(VAULT_ID, vec![rel.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        let result = storage.read_relationships(VAULT_ID, &key, Revision::zero()).await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], rel);
    }

    #[tokio::test]
    async fn test_delete_relationships_removes_data() {
        let storage = create_storage();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        storage.write_relationships(VAULT_ID, vec![rel]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        storage.delete_relationships(VAULT_ID, &key).await.unwrap();

        let result = storage.read_relationships(VAULT_ID, &key, Revision::zero()).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_list_relationships_with_filters() {
        let storage = create_storage();
        let rel1 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:b", "editor", "user:bob");
        storage.write_relationships(VAULT_ID, vec![rel1, rel2]).await.unwrap();

        let result = storage
            .list_relationships(VAULT_ID, Some("doc:a"), None, None, Revision::zero())
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].resource, "doc:a");
    }

    #[tokio::test]
    async fn test_get_revision_returns_current() {
        let storage = create_storage();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        storage.write_relationships(VAULT_ID, vec![rel]).await.unwrap();

        let rev = storage.get_revision(VAULT_ID).await.unwrap();

        assert_eq!(rev, Revision(1));
    }

    #[tokio::test]
    async fn test_list_resources_by_type() {
        let storage = create_storage();
        let rel1 = test_rel(VAULT_ID, "doc:a", "viewer", "user:alice");
        let rel2 = test_rel(VAULT_ID, "doc:b", "viewer", "user:alice");
        let rel3 = test_rel(VAULT_ID, "folder:root", "viewer", "user:alice");
        storage.write_relationships(VAULT_ID, vec![rel1, rel2, rel3]).await.unwrap();

        let result =
            storage.list_resources_by_type(VAULT_ID, "doc", Revision::zero()).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&"doc:a".to_string()));
        assert!(result.contains(&"doc:b".to_string()));
    }

    #[tokio::test]
    async fn test_read_changes_returns_events() {
        let storage = create_storage();
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        storage.write_relationships(VAULT_ID, vec![rel]).await.unwrap();

        let events = storage.read_changes(VAULT_ID, Revision::zero(), &[], None).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, ChangeOperation::Create);
    }

    // =========================================================================
    // ORGANIZATION OPERATION TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_create_organization_returns_org() {
        let storage = create_storage();
        let org = test_org(ORG_ID, "Acme Corp");

        let result = storage.create_organization(org.clone()).await.unwrap();

        assert_eq!(result.id, ORG_ID);
        assert_eq!(result.name, "Acme Corp");
    }

    #[tokio::test]
    async fn test_get_organization_returns_created() {
        let storage = create_storage();
        let org = test_org(ORG_ID, "Acme Corp");
        storage.create_organization(org).await.unwrap();

        let result = storage.get_organization(ORG_ID).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "Acme Corp");
    }

    #[tokio::test]
    async fn test_get_organization_returns_none_for_missing() {
        let storage = create_storage();

        let result = storage.get_organization(999).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_organizations_returns_all() {
        let storage = create_storage();
        storage.create_organization(test_org(1, "Org A")).await.unwrap();
        storage.create_organization(test_org(2, "Org B")).await.unwrap();

        let result = storage.list_organizations(None).await.unwrap();

        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_update_organization_persists() {
        let storage = create_storage();
        storage.create_organization(test_org(ORG_ID, "Old Name")).await.unwrap();

        storage.update_organization(test_org(ORG_ID, "New Name")).await.unwrap();

        let result = storage.get_organization(ORG_ID).await.unwrap().unwrap();
        assert_eq!(result.name, "New Name");
    }

    #[tokio::test]
    async fn test_delete_organization_removes() {
        let storage = create_storage();
        storage.create_organization(test_org(ORG_ID, "Acme Corp")).await.unwrap();

        storage.delete_organization(ORG_ID).await.unwrap();

        let result = storage.get_organization(ORG_ID).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_create_duplicate_organization_returns_conflict() {
        let storage = create_storage();
        storage.create_organization(test_org(ORG_ID, "Acme Corp")).await.unwrap();

        let result = storage.create_organization(test_org(ORG_ID, "Other")).await;

        assert!(matches!(result, Err(StoreError::Conflict)));
    }

    // =========================================================================
    // VAULT OPERATION TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_create_vault_returns_vault() {
        let storage = create_storage();
        let vault = test_vault(VAULT_ID, ORG_ID, "Production");

        let result = storage.create_vault(vault).await.unwrap();

        assert_eq!(result.id, VAULT_ID);
        assert_eq!(result.name, "Production");
    }

    #[tokio::test]
    async fn test_get_vault_returns_created() {
        let storage = create_storage();
        storage.create_vault(test_vault(VAULT_ID, ORG_ID, "Production")).await.unwrap();

        let result = storage.get_vault(VAULT_ID).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "Production");
    }

    #[tokio::test]
    async fn test_list_vaults_for_organization() {
        let storage = create_storage();
        storage.create_vault(test_vault(100, ORG_ID, "Vault A")).await.unwrap();
        storage.create_vault(test_vault(101, ORG_ID, "Vault B")).await.unwrap();
        storage.create_vault(test_vault(200, 2, "Other Org Vault")).await.unwrap();

        let result = storage.list_vaults_for_organization(ORG_ID).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|v| v.organization == ORG_ID));
    }

    #[tokio::test]
    async fn test_update_vault_persists() {
        let storage = create_storage();
        storage.create_vault(test_vault(VAULT_ID, ORG_ID, "Old Name")).await.unwrap();

        storage.update_vault(test_vault(VAULT_ID, ORG_ID, "New Name")).await.unwrap();

        let result = storage.get_vault(VAULT_ID).await.unwrap().unwrap();
        assert_eq!(result.name, "New Name");
    }

    #[tokio::test]
    async fn test_delete_vault_removes() {
        let storage = create_storage();
        storage.create_vault(test_vault(VAULT_ID, ORG_ID, "Production")).await.unwrap();

        storage.delete_vault(VAULT_ID).await.unwrap();

        let result = storage.get_vault(VAULT_ID).await.unwrap();
        assert!(result.is_none());
    }

    // =========================================================================
    // SYSTEM CONFIG TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_get_system_config_returns_none_initially() {
        let storage = create_storage();

        let result = storage.get_system_config().await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_set_system_config_persists() {
        let storage = create_storage();
        let config = SystemConfig::new(ORG_ID, VAULT_ID);

        storage.set_system_config(config).await.unwrap();

        let result = storage.get_system_config().await.unwrap();
        assert!(result.is_some());
        let retrieved = result.unwrap();
        assert_eq!(retrieved.default_organization, ORG_ID);
        assert_eq!(retrieved.default_vault, VAULT_ID);
    }

    #[tokio::test]
    async fn test_set_system_config_overwrites() {
        let storage = create_storage();
        storage.set_system_config(SystemConfig::new(1, 100)).await.unwrap();
        storage.set_system_config(SystemConfig::new(2, 200)).await.unwrap();

        let result = storage.get_system_config().await.unwrap().unwrap();
        assert_eq!(result.default_organization, 2);
        assert_eq!(result.default_vault, 200);
    }

    // =========================================================================
    // ERROR MAPPING TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_update_nonexistent_organization_returns_not_found() {
        let storage = create_storage();

        let result = storage.update_organization(test_org(999, "Ghost")).await;

        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_organization_returns_not_found() {
        let storage = create_storage();

        let result = storage.delete_organization(999).await;

        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn test_update_nonexistent_vault_returns_not_found() {
        let storage = create_storage();

        let result = storage.update_vault(test_vault(999, 1, "Ghost")).await;

        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_vault_returns_not_found() {
        let storage = create_storage();

        let result = storage.delete_vault(999).await;

        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    // =========================================================================
    // INTEGRATION TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_full_workflow() {
        let storage = create_storage();

        // Create organization
        let org = storage.create_organization(test_org(ORG_ID, "Acme Corp")).await.unwrap();
        assert_eq!(org.name, "Acme Corp");

        // Create vault
        let vault = storage.create_vault(test_vault(VAULT_ID, ORG_ID, "Production")).await.unwrap();
        assert_eq!(vault.name, "Production");

        // Write relationship
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rev = storage.write_relationships(VAULT_ID, vec![rel.clone()]).await.unwrap();
        assert_eq!(rev, Revision(1));

        // Read relationship
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        let rels = storage.read_relationships(VAULT_ID, &key, Revision::zero()).await.unwrap();
        assert_eq!(rels.len(), 1);

        // Set system config
        let config = SystemConfig::new(ORG_ID, VAULT_ID);
        storage.set_system_config(config).await.unwrap();
        let retrieved_config = storage.get_system_config().await.unwrap().unwrap();
        assert_eq!(retrieved_config.default_vault, VAULT_ID);
    }
}
