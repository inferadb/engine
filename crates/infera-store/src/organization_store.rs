//! Organization store trait and implementations
//!
//! Provides storage operations for Organizations in the multi-tenant system.

use async_trait::async_trait;
use infera_types::{Organization, StoreResult};

/// Trait for organization storage operations
#[async_trait]
pub trait OrganizationStore: Send + Sync {
    /// Create a new organization
    async fn create_organization(&self, organization: Organization) -> StoreResult<Organization>;

    /// Get an organization by ID
    async fn get_organization(&self, id: i64) -> StoreResult<Option<Organization>>;

    /// List all organizations (admin operation)
    async fn list_organizations(&self, limit: Option<usize>) -> StoreResult<Vec<Organization>>;

    /// Delete an organization (cascades to vaults and relationships)
    async fn delete_organization(&self, id: i64) -> StoreResult<()>;

    /// Update an organization
    async fn update_organization(&self, organization: Organization) -> StoreResult<Organization>;
}
