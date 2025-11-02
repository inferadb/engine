//! # Infera Store - Storage Abstraction Layer
//!
//! Provides abstract database operations and revision consistency management.

use async_trait::async_trait;
use infera_types::{
    ChangeEvent, DeleteFilter, Relationship, RelationshipKey, Revision, StoreError, StoreResult,
};
use uuid::Uuid;

pub mod account_store;
pub mod factory;
#[cfg(feature = "fdb")]
pub mod foundationdb;
pub mod memory;
pub mod metrics;
pub mod vault_store;

pub use account_store::AccountStore;
pub use factory::{BackendType, StorageConfig, StorageFactory};
pub use memory::MemoryBackend;
pub use metrics::{MetricsSnapshot, OpTimer, StoreMetrics};
pub use vault_store::VaultStore;

#[cfg(feature = "fdb")]
pub use foundationdb::FoundationDBBackend;

type Result<T> = StoreResult<T>;

/// The abstract relationship store interface
///
/// All operations are scoped to a specific Vault for multi-tenant isolation.
#[async_trait]
pub trait RelationshipStore: Send + Sync {
    /// Read relationships matching the key at a specific revision within a vault
    async fn read(
        &self,
        vault: Uuid,
        key: &RelationshipKey,
        revision: Revision,
    ) -> Result<Vec<Relationship>>;

    /// Write relationships and return the new revision
    /// All relationships must have their vault_id set correctly
    async fn write(&self, vault: Uuid, relationships: Vec<Relationship>) -> Result<Revision>;

    /// Get the current revision for a vault
    async fn get_revision(&self, vault: Uuid) -> Result<Revision>;

    /// Delete relationships matching the key within a vault
    async fn delete(&self, vault: Uuid, key: &RelationshipKey) -> Result<Revision>;

    /// Delete relationships matching a filter within a vault
    /// Returns (revision, count_deleted)
    /// The filter must have at least one field set to avoid deleting all relationships
    async fn delete_by_filter(
        &self,
        vault: Uuid,
        filter: &DeleteFilter,
        limit: Option<usize>,
    ) -> Result<(Revision, usize)>;

    /// List all distinct resources of a given type prefix within a vault
    /// Returns unique resource identifiers like ["document:1", "document:2"]
    async fn list_resources_by_type(
        &self,
        vault: Uuid,
        resource_type: &str,
        revision: Revision,
    ) -> Result<Vec<String>>;

    /// List relationships with optional filtering within a vault
    /// All filter fields are optional and can be combined:
    /// - resource: Filter by exact resource match (e.g., "doc:readme")
    /// - relation: Filter by relation (e.g., "viewer")
    /// - subject: Filter by exact subject match (e.g., "user:alice")
    /// Returns all relationships matching the filter criteria at the specified revision
    async fn list_relationships(
        &self,
        vault: Uuid,
        resource: Option<&str>,
        relation: Option<&str>,
        subject: Option<&str>,
        revision: Revision,
    ) -> Result<Vec<Relationship>>;

    /// Get metrics snapshot (optional, returns None if not supported)
    fn metrics(&self) -> Option<MetricsSnapshot> {
        None
    }

    /// Append a change event to the change log for a vault
    /// This is called automatically by write/delete operations
    async fn append_change(&self, vault: Uuid, event: ChangeEvent) -> Result<()>;

    /// Read change events from the change log starting from a specific revision within a vault
    /// Filters by resource types if provided (empty list means all types)
    /// Returns events in ascending revision order
    async fn read_changes(
        &self,
        vault: Uuid,
        start_revision: Revision,
        resource_types: &[String],
        limit: Option<usize>,
    ) -> Result<Vec<ChangeEvent>>;

    /// Get the latest change log revision for a vault
    /// Returns Revision::zero() if no changes exist
    async fn get_change_log_revision(&self, vault: Uuid) -> Result<Revision>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revision_ordering() {
        let r1 = Revision(1);
        let r2 = Revision(2);
        assert!(r1 < r2);
        assert_eq!(r1.next(), r2);
    }
}
