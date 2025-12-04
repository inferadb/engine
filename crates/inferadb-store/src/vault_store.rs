//! Vault store trait and implementations
//!
//! Provides storage operations for Vaults in the multi-tenant system.

use async_trait::async_trait;
use infera_types::{StoreResult, SystemConfig, Vault};

/// Trait for vault storage operations
#[async_trait]
pub trait VaultStore: Send + Sync {
    /// Create a new vault
    async fn create_vault(&self, vault: Vault) -> StoreResult<Vault>;

    /// Get a vault by ID
    async fn get_vault(&self, id: i64) -> StoreResult<Option<Vault>>;

    /// List all vaults for an organization
    async fn list_vaults_for_organization(&self, organization_id: i64) -> StoreResult<Vec<Vault>>;

    /// Delete a vault (cascades to relationships)
    async fn delete_vault(&self, id: i64) -> StoreResult<()>;

    /// Update a vault
    async fn update_vault(&self, vault: Vault) -> StoreResult<Vault>;

    /// Get the system configuration (default vault info)
    async fn get_system_config(&self) -> StoreResult<Option<SystemConfig>>;

    /// Set the system configuration (default vault info)
    async fn set_system_config(&self, config: SystemConfig) -> StoreResult<()>;
}
