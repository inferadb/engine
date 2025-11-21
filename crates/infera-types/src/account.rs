//! Account type
//!
//! Represents a user or organization that owns Vaults in InferaDB's multi-tenant system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An Account represents a user or organization that owns one or more Vaults.
///
/// Accounts are the top-level ownership entity in InferaDB's multi-tenancy model.
/// Each Account can own zero, one, or many Vaults, providing isolation boundaries
/// for authorization data.
/// IDs are Snowflake IDs (i64) from the Management API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Unique identifier for this account (Snowflake ID from Management API)
    pub id: i64,

    /// Human-readable name for the account
    pub name: String,

    /// When this account was created
    pub created_at: DateTime<Utc>,

    /// When this account was last updated
    pub updated_at: DateTime<Utc>,
}

impl Account {
    /// Create a new Account with a specific ID
    pub fn new(id: i64, name: String) -> Self {
        let now = Utc::now();
        Self { id, name, created_at: now, updated_at: now }
    }

    /// Create an Account with a specific ID (alias for new)
    pub fn with_id(id: i64, name: String) -> Self {
        Self::new(id, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_new() {
        let id: i64 = 98765432109876;
        let account = Account::new(id, "Test Account".to_string());
        assert_eq!(account.id, id);
        assert_eq!(account.name, "Test Account");
        assert!(account.created_at <= Utc::now());
        assert_eq!(account.created_at, account.updated_at);
    }

    #[test]
    fn test_account_with_id() {
        let id: i64 = 98765432109876;
        let account = Account::with_id(id, "Test Account".to_string());
        assert_eq!(account.id, id);
        assert_eq!(account.name, "Test Account");
    }

    #[test]
    fn test_account_serialization() {
        let id: i64 = 98765432109876;
        let account = Account::new(id, "Test Account".to_string());
        let json = serde_json::to_string(&account).unwrap();
        let deserialized: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(account, deserialized);
    }
}
