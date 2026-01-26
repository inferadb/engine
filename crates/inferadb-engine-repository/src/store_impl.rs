//! Implementation of `inferadb-engine-store` traits for [`EngineStorage`].
//!
//! This module provides trait implementations that allow [`EngineStorage`] to be
//! used as `Arc<dyn InferaStore>`, enabling drop-in replacement of the existing
//! store implementations.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                  API Layer                      │
//! │      (Uses Arc<dyn InferaStore>)                │
//! ├─────────────────────────────────────────────────┤
//! │              Store Trait Impls                  │
//! │  RelationshipStore, OrganizationStore,          │
//! │  VaultStore, InferaStore for EngineStorage<S>   │
//! ├─────────────────────────────────────────────────┤
//! │                EngineStorage<S>                 │
//! │    (Delegates to Repository methods)            │
//! ├─────────────────────────────────────────────────┤
//! │              StorageBackend (S)                 │
//! └─────────────────────────────────────────────────┘
//! ```

use std::any::Any;

use async_trait::async_trait;
use inferadb_engine_store::{
    InferaStore, MetricsSnapshot, OrganizationStore, RelationshipStore, VaultStore,
};
use inferadb_engine_types::{
    ChangeEvent, DeleteFilter, Organization, Relationship, RelationshipKey, Revision, StoreResult,
    SystemConfig, Vault,
};
use inferadb_storage::StorageBackend;

use crate::{RepositoryError, storage::EngineStorage};

/// Convert a repository error to a store error.
fn to_store_error(err: RepositoryError) -> inferadb_engine_types::StoreError {
    use inferadb_engine_types::StoreError;
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
fn to_store_result<T>(result: crate::RepositoryResult<T>) -> StoreResult<T> {
    result.map_err(to_store_error)
}

// =============================================================================
// RelationshipStore Implementation
// =============================================================================

#[async_trait]
impl<S> RelationshipStore for EngineStorage<S>
where
    S: StorageBackend + Send + Sync + 'static,
{
    async fn read(
        &self,
        vault: i64,
        key: &RelationshipKey,
        revision: Revision,
    ) -> StoreResult<Vec<Relationship>> {
        to_store_result(self.relationships().read(vault, key, revision).await)
    }

    async fn write(&self, vault: i64, relationships: Vec<Relationship>) -> StoreResult<Revision> {
        to_store_result(self.relationships().write(vault, relationships).await)
    }

    async fn get_revision(&self, vault: i64) -> StoreResult<Revision> {
        to_store_result(self.relationships().get_revision(vault).await)
    }

    async fn delete(&self, vault: i64, key: &RelationshipKey) -> StoreResult<Revision> {
        to_store_result(self.relationships().delete(vault, key).await)
    }

    async fn delete_by_filter(
        &self,
        vault: i64,
        filter: &DeleteFilter,
        limit: Option<usize>,
    ) -> StoreResult<(Revision, usize)> {
        to_store_result(self.relationships().delete_by_filter(vault, filter, limit).await)
    }

    async fn list_resources_by_type(
        &self,
        vault: i64,
        resource_type: &str,
        revision: Revision,
    ) -> StoreResult<Vec<String>> {
        to_store_result(
            self.relationships().list_resources_by_type(vault, resource_type, revision).await,
        )
    }

    async fn list_relationships(
        &self,
        vault: i64,
        resource: Option<&str>,
        relation: Option<&str>,
        subject: Option<&str>,
        revision: Revision,
    ) -> StoreResult<Vec<Relationship>> {
        to_store_result(
            self.relationships()
                .list_relationships(vault, resource, relation, subject, revision)
                .await,
        )
    }

    fn metrics(&self) -> Option<MetricsSnapshot> {
        // Repository-based storage doesn't have built-in metrics yet
        None
    }

    async fn append_change(&self, vault: i64, event: ChangeEvent) -> StoreResult<()> {
        to_store_result(self.relationships().append_change(vault, event).await)
    }

    async fn read_changes(
        &self,
        vault: i64,
        start_revision: Revision,
        resource_types: &[String],
        limit: Option<usize>,
    ) -> StoreResult<Vec<ChangeEvent>> {
        to_store_result(
            self.relationships().read_changes(vault, start_revision, resource_types, limit).await,
        )
    }

    async fn get_change_log_revision(&self, vault: i64) -> StoreResult<Revision> {
        to_store_result(self.relationships().get_change_log_revision(vault).await)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// =============================================================================
// OrganizationStore Implementation
// =============================================================================

#[async_trait]
impl<S> OrganizationStore for EngineStorage<S>
where
    S: StorageBackend + Send + Sync + 'static,
{
    async fn create_organization(&self, organization: Organization) -> StoreResult<Organization> {
        to_store_result(self.organizations().create(organization).await)
    }

    async fn get_organization(&self, id: i64) -> StoreResult<Option<Organization>> {
        to_store_result(self.organizations().get(id).await)
    }

    async fn list_organizations(&self, limit: Option<usize>) -> StoreResult<Vec<Organization>> {
        to_store_result(self.organizations().list(limit).await)
    }

    async fn delete_organization(&self, id: i64) -> StoreResult<()> {
        // Delegate to inherent method which handles cascade deletion
        EngineStorage::delete_organization(self, id).await
    }

    async fn update_organization(&self, organization: Organization) -> StoreResult<Organization> {
        to_store_result(self.organizations().update(organization).await)
    }
}

// =============================================================================
// VaultStore Implementation
// =============================================================================

#[async_trait]
impl<S> VaultStore for EngineStorage<S>
where
    S: StorageBackend + Send + Sync + 'static,
{
    async fn create_vault(&self, vault: Vault) -> StoreResult<Vault> {
        to_store_result(self.vaults().create(vault).await)
    }

    async fn get_vault(&self, id: i64) -> StoreResult<Option<Vault>> {
        to_store_result(self.vaults().get(id).await)
    }

    async fn list_vaults_for_organization(&self, organization_id: i64) -> StoreResult<Vec<Vault>> {
        to_store_result(self.vaults().list_by_organization(organization_id).await)
    }

    async fn delete_vault(&self, id: i64) -> StoreResult<()> {
        to_store_result(self.vaults().delete(id).await)
    }

    async fn update_vault(&self, vault: Vault) -> StoreResult<Vault> {
        to_store_result(self.vaults().update(vault).await)
    }

    async fn get_system_config(&self) -> StoreResult<Option<SystemConfig>> {
        // Read directly from storage using the system config key
        let key = crate::keys::system::config();
        match self.vaults().storage().get(&key).await {
            Ok(Some(data)) => {
                let config: SystemConfig = serde_json::from_slice(&data)
                    .map_err(|e| inferadb_engine_types::StoreError::Internal(e.to_string()))?;
                Ok(Some(config))
            },
            Ok(None) => Ok(None),
            Err(e) => Err(to_store_error(e.into())),
        }
    }

    async fn set_system_config(&self, config: SystemConfig) -> StoreResult<()> {
        let key = crate::keys::system::config();
        let data = serde_json::to_vec(&config)
            .map_err(|e| inferadb_engine_types::StoreError::Internal(e.to_string()))?;
        self.vaults().storage().set(key, data).await.map_err(|e| to_store_error(e.into()))
    }
}

// =============================================================================
// InferaStore Implementation
// =============================================================================

impl<S> InferaStore for EngineStorage<S> where S: StorageBackend + Send + Sync + 'static {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use inferadb_engine_store::InferaStore;
    use inferadb_engine_types::{Organization, Relationship, RelationshipKey, Revision, Vault};
    use inferadb_storage::MemoryBackend;

    use crate::EngineStorage;

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
    // TRAIT OBJECT USAGE TESTS
    // =========================================================================

    #[tokio::test]
    async fn test_can_use_as_dyn_infera_store() {
        let storage = create_storage();
        let store: Arc<dyn InferaStore> = Arc::new(storage);

        // Verify basic operations work through trait object
        let rev = store.get_revision(VAULT_ID).await.unwrap();
        assert_eq!(rev, Revision::zero());
    }

    #[tokio::test]
    async fn test_relationship_store_trait_via_dyn() {
        let storage = create_storage();
        let store: Arc<dyn InferaStore> = Arc::new(storage);

        // Write through trait object
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rev = store.write(VAULT_ID, vec![rel.clone()]).await.unwrap();
        assert_eq!(rev, Revision(1));

        // Read through trait object
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: Some("user:alice".to_string()),
        };
        let result = store.read(VAULT_ID, &key, Revision::zero()).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], rel);
    }

    #[tokio::test]
    async fn test_organization_store_trait_via_dyn() {
        let storage = create_storage();
        let store: Arc<dyn InferaStore> = Arc::new(storage);

        // Create organization through trait object
        let org = test_org(ORG_ID, "Acme Corp");
        let created = store.create_organization(org).await.unwrap();
        assert_eq!(created.name, "Acme Corp");

        // Get organization through trait object
        let retrieved = store.get_organization(ORG_ID).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Acme Corp");

        // List organizations
        let orgs = store.list_organizations(None).await.unwrap();
        assert_eq!(orgs.len(), 1);

        // Update organization
        let updated = store.update_organization(test_org(ORG_ID, "Acme Inc")).await.unwrap();
        assert_eq!(updated.name, "Acme Inc");

        // Delete organization
        store.delete_organization(ORG_ID).await.unwrap();
        let gone = store.get_organization(ORG_ID).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_vault_store_trait_via_dyn() {
        let storage = create_storage();
        let store: Arc<dyn InferaStore> = Arc::new(storage);

        // Create vault through trait object
        let vault = test_vault(VAULT_ID, ORG_ID, "Production");
        let created = store.create_vault(vault).await.unwrap();
        assert_eq!(created.name, "Production");

        // Get vault through trait object
        let retrieved = store.get_vault(VAULT_ID).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Production");

        // List vaults for organization
        let vaults = store.list_vaults_for_organization(ORG_ID).await.unwrap();
        assert_eq!(vaults.len(), 1);

        // Update vault
        let updated = store.update_vault(test_vault(VAULT_ID, ORG_ID, "Staging")).await.unwrap();
        assert_eq!(updated.name, "Staging");

        // Delete vault
        store.delete_vault(VAULT_ID).await.unwrap();
        let gone = store.get_vault(VAULT_ID).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_full_workflow_via_dyn_infera_store() {
        let storage = create_storage();
        let store: Arc<dyn InferaStore> = Arc::new(storage);

        // Create organization
        store.create_organization(test_org(ORG_ID, "Acme Corp")).await.unwrap();

        // Create vault
        store.create_vault(test_vault(VAULT_ID, ORG_ID, "Production")).await.unwrap();

        // Write relationships
        let rel = test_rel(VAULT_ID, "doc:readme", "viewer", "user:alice");
        let rev = store.write(VAULT_ID, vec![rel]).await.unwrap();
        assert_eq!(rev, Revision(1));

        // Read relationships
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };
        let rels = store.read(VAULT_ID, &key, Revision::zero()).await.unwrap();
        assert_eq!(rels.len(), 1);

        // Get revision
        let current_rev = store.get_revision(VAULT_ID).await.unwrap();
        assert_eq!(current_rev, Revision(1));
    }
}
