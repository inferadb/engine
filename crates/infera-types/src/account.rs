//! Account type
//!
//! Represents a user or organization that owns Vaults in InferaDB's multi-tenant system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An Account represents a user or organization that owns one or more Vaults.
///
/// Accounts are the top-level ownership entity in InferaDB's multi-tenancy model.
/// Each Account can own zero, one, or many Vaults, providing isolation boundaries
/// for authorization data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Unique identifier for this account
    pub id: Uuid,

    /// Human-readable name for the account
    pub name: String,

    /// When this account was created
    pub created_at: DateTime<Utc>,

    /// When this account was last updated
    pub updated_at: DateTime<Utc>,
}

impl Account {
    /// Create a new Account with a generated UUID
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create an Account with a specific ID (useful for testing)
    pub fn with_id(id: Uuid, name: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_new() {
        let account = Account::new("Test Account".to_string());
        assert_eq!(account.name, "Test Account");
        assert!(account.created_at <= Utc::now());
        assert_eq!(account.created_at, account.updated_at);
    }

    #[test]
    fn test_account_with_id() {
        let id = Uuid::new_v4();
        let account = Account::with_id(id, "Test Account".to_string());
        assert_eq!(account.id, id);
        assert_eq!(account.name, "Test Account");
    }

    #[test]
    fn test_account_serialization() {
        let account = Account::new("Test Account".to_string());
        let json = serde_json::to_string(&account).unwrap();
        let deserialized: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(account, deserialized);
    }
}
