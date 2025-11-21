//! Account store trait and implementations
//!
//! Provides storage operations for Accounts in the multi-tenant system.

use async_trait::async_trait;
use infera_types::{Account, StoreResult};

/// Trait for account storage operations
#[async_trait]
pub trait AccountStore: Send + Sync {
    /// Create a new account
    async fn create_account(&self, account: Account) -> StoreResult<Account>;

    /// Get an account by ID
    async fn get_account(&self, id: i64) -> StoreResult<Option<Account>>;

    /// List all accounts (admin operation)
    async fn list_accounts(&self, limit: Option<usize>) -> StoreResult<Vec<Account>>;

    /// Delete an account (cascades to vaults and relationships)
    async fn delete_account(&self, id: i64) -> StoreResult<()>;

    /// Update an account
    async fn update_account(&self, account: Account) -> StoreResult<Account>;
}
