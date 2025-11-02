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
    pub account_id: Uuid,

    /// Human-readable name for the vault
    pub name: String,

    /// When this vault was created
    pub created_at: DateTime<Utc>,

    /// When this vault was last updated
    pub updated_at: DateTime<Utc>,
}

impl Vault {
    /// Create a new Vault with a generated UUID
    pub fn new(account_id: Uuid, name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            account_id,
            name,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a Vault with a specific ID (useful for testing)
    pub fn with_id(id: Uuid, account_id: Uuid, name: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            account_id,
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
    pub default_vault_id: Uuid,

    /// The default account ID that owns the default vault
    pub default_account_id: Uuid,
}

impl SystemConfig {
    /// Create a new SystemConfig
    pub fn new(default_account_id: Uuid, default_vault_id: Uuid) -> Self {
        Self {
            default_vault_id,
            default_account_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_new() {
        let account_id = Uuid::new_v4();
        let vault = Vault::new(account_id, "Test Vault".to_string());
        assert_eq!(vault.account_id, account_id);
        assert_eq!(vault.name, "Test Vault");
        assert!(vault.created_at <= Utc::now());
        assert_eq!(vault.created_at, vault.updated_at);
    }

    #[test]
    fn test_vault_with_id() {
        let id = Uuid::new_v4();
        let account_id = Uuid::new_v4();
        let vault = Vault::with_id(id, account_id, "Test Vault".to_string());
        assert_eq!(vault.id, id);
        assert_eq!(vault.account_id, account_id);
        assert_eq!(vault.name, "Test Vault");
    }

    #[test]
    fn test_vault_serialization() {
        let account_id = Uuid::new_v4();
        let vault = Vault::new(account_id, "Test Vault".to_string());
        let json = serde_json::to_string(&vault).unwrap();
        let deserialized: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(vault, deserialized);
    }

    #[test]
    fn test_system_config() {
        let account_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4();
        let config = SystemConfig::new(account_id, vault_id);
        assert_eq!(config.default_account_id, account_id);
        assert_eq!(config.default_vault_id, vault_id);
    }

    #[test]
    fn test_system_config_serialization() {
        let config = SystemConfig::new(Uuid::new_v4(), Uuid::new_v4());
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SystemConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }
}
