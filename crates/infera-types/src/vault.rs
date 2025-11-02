//! Vault type
//!
//! Represents an isolated authorization domain owned by an Account.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Vault represents an isolated authorization domain.
///
/// All authorization data (relationships, policies, schemas) are scoped to a specific Vault.
/// Vaults provide complete data isolation in InferaDB's multi-tenant system, ensuring that
/// one tenant's data cannot be accessed by another tenant.
///
/// Each Vault is owned by exactly one Account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    /// Unique identifier for this vault
    pub id: Uuid,

    /// ID of the Account that owns this vault
    pub account: Uuid,

    /// Human-readable name for the vault
    pub name: String,

    /// When this vault was created
    pub created_at: DateTime<Utc>,

    /// When this vault was last updated
    pub updated_at: DateTime<Utc>,
}

impl Vault {
    /// Create a new Vault with a generated UUID
    pub fn new(account: Uuid, name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            account,
            name,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a Vault with a specific ID (useful for testing)
    pub fn with_id(id: Uuid, account: Uuid, name: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            account,
            name,
            created_at: now,
            updated_at: now,
        }
    }
}

/// System configuration for default vault
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemConfig {
    /// The default vault ID used when authentication is disabled
    pub default_vault: Uuid,

    /// The default account ID that owns the default vault
    pub default_account: Uuid,
}

impl SystemConfig {
    /// Create a new SystemConfig
    pub fn new(default_account: Uuid, default_vault: Uuid) -> Self {
        Self {
            default_vault,
            default_account,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_new() {
        let account = Uuid::new_v4();
        let vault = Vault::new(account, "Test Vault".to_string());
        assert_eq!(vault.account, account);
        assert_eq!(vault.name, "Test Vault");
        assert!(vault.created_at <= Utc::now());
        assert_eq!(vault.created_at, vault.updated_at);
    }

    #[test]
    fn test_vault_with_id() {
        let id = Uuid::new_v4();
        let account = Uuid::new_v4();
        let vault = Vault::with_id(id, account, "Test Vault".to_string());
        assert_eq!(vault.id, id);
        assert_eq!(vault.account, account);
        assert_eq!(vault.name, "Test Vault");
    }

    #[test]
    fn test_vault_serialization() {
        let account = Uuid::new_v4();
        let vault = Vault::new(account, "Test Vault".to_string());
        let json = serde_json::to_string(&vault).unwrap();
        let deserialized: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(vault, deserialized);
    }

    #[test]
    fn test_system_config() {
        let account = Uuid::new_v4();
        let vault = Uuid::new_v4();
        let config = SystemConfig::new(account, vault);
        assert_eq!(config.default_account, account);
        assert_eq!(config.default_vault, vault);
    }

    #[test]
    fn test_system_config_serialization() {
        let config = SystemConfig::new(Uuid::new_v4(), Uuid::new_v4());
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SystemConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }
}
