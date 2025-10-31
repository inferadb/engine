//! # Infera Store - Storage Abstraction Layer
//!
//! Provides abstract database operations and revision consistency management.

use async_trait::async_trait;
use infera_types::{
    DeleteFilter, Relationship, RelationshipKey, Revision, StoreError, StoreResult,
};

pub mod factory;
#[cfg(feature = "fdb")]
pub mod foundationdb;
pub mod memory;
pub mod metrics;

pub use factory::{BackendType, StorageConfig, StorageFactory};
pub use memory::MemoryBackend;
pub use metrics::{MetricsSnapshot, OpTimer, StoreMetrics};

#[cfg(feature = "fdb")]
pub use foundationdb::FoundationDBBackend;

type Result<T> = StoreResult<T>;

/// The abstract relationship store interface
#[async_trait]
pub trait RelationshipStore: Send + Sync {
    /// Read relationships matching the key at a specific revision
    async fn read(&self, key: &RelationshipKey, revision: Revision) -> Result<Vec<Relationship>>;

    /// Write relationships and return the new revision
    async fn write(&self, relationships: Vec<Relationship>) -> Result<Revision>;

    /// Get the current revision
    async fn get_revision(&self) -> Result<Revision>;

    /// Delete relationships matching the key
    async fn delete(&self, key: &RelationshipKey) -> Result<Revision>;

    /// Delete relationships matching a filter
    /// Returns (revision, count_deleted)
    /// The filter must have at least one field set to avoid deleting all relationships
    async fn delete_by_filter(
        &self,
        filter: &DeleteFilter,
        limit: Option<usize>,
    ) -> Result<(Revision, usize)>;

    /// List all distinct resources of a given type prefix (e.g., "document", "folder")
    /// Returns unique resource identifiers like ["document:1", "document:2"]
    async fn list_resources_by_type(
        &self,
        resource_type: &str,
        revision: Revision,
    ) -> Result<Vec<String>>;

    /// List relationships with optional filtering
    /// All filter fields are optional and can be combined:
    /// - resource: Filter by exact resource match (e.g., "doc:readme")
    /// - relation: Filter by relation (e.g., "viewer")
    /// - subject: Filter by exact subject match (e.g., "user:alice")
    /// Returns all relationships matching the filter criteria at the specified revision
    async fn list_relationships(
        &self,
        resource: Option<&str>,
        relation: Option<&str>,
        subject: Option<&str>,
        revision: Revision,
    ) -> Result<Vec<Relationship>>;

    /// Get metrics snapshot (optional, returns None if not supported)
    fn metrics(&self) -> Option<MetricsSnapshot> {
        None
    }
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
