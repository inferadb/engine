//! Vault type
//!
//! Represents an isolated authorization domain owned by an Organization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A Vault represents an isolated authorization domain.
///
/// All authorization data (relationships, policies, schemas) are scoped to a specific Vault.
/// Vaults provide complete data isolation in InferaDB's multi-tenant system, ensuring that
/// one tenant's data cannot be accessed by another tenant.
///
/// Each Vault is owned by exactly one Organization.
/// IDs are Snowflake IDs (i64) from the Management API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    /// Unique identifier for this vault (Snowflake ID from Management API)
    pub id: i64,

    /// ID of the Organization that owns this vault (Snowflake ID)
    pub organization: i64,

    /// Human-readable name for the vault
    pub name: String,

    /// When this vault was created
    pub created_at: DateTime<Utc>,

    /// When this vault was last updated
    pub updated_at: DateTime<Utc>,
}

impl Vault {
    /// Create a new Vault with a specific ID
    pub fn new(id: i64, organization: i64, name: String) -> Self {
        let now = Utc::now();
        Self { id, organization, name, created_at: now, updated_at: now }
    }

    /// Create a Vault with a specific ID (alias for new)
    pub fn with_id(id: i64, organization: i64, name: String) -> Self {
        Self::new(id, organization, name)
    }
}

/// System configuration for default vault
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemConfig {
    /// The default vault ID used when authentication is disabled (Snowflake ID)
    pub default_vault: i64,

    /// The default organization ID that owns the default vault (Snowflake ID)
    pub default_organization: i64,
}

impl SystemConfig {
    /// Create a new SystemConfig
    pub fn new(default_organization: i64, default_vault: i64) -> Self {
        Self { default_vault, default_organization }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_new() {
        let id: i64 = 12345678901234;
        let organization: i64 = 98765432109876;
        let vault = Vault::new(id, organization, "Test Vault".to_string());
        assert_eq!(vault.organization, organization);
        assert_eq!(vault.name, "Test Vault");
        assert!(vault.created_at <= Utc::now());
        assert_eq!(vault.created_at, vault.updated_at);
    }

    #[test]
    fn test_vault_with_id() {
        let id: i64 = 12345678901234;
        let organization: i64 = 98765432109876;
        let vault = Vault::with_id(id, organization, "Test Vault".to_string());
        assert_eq!(vault.id, id);
        assert_eq!(vault.organization, organization);
        assert_eq!(vault.name, "Test Vault");
    }

    #[test]
    fn test_vault_serialization() {
        let id: i64 = 12345678901234;
        let organization: i64 = 98765432109876;
        let vault = Vault::new(id, organization, "Test Vault".to_string());
        let json = serde_json::to_string(&vault).unwrap();
        let deserialized: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(vault, deserialized);
    }

    #[test]
    fn test_system_config() {
        let organization: i64 = 98765432109876;
        let vault: i64 = 12345678901234;
        let config = SystemConfig::new(organization, vault);
        assert_eq!(config.default_organization, organization);
        assert_eq!(config.default_vault, vault);
    }

    #[test]
    fn test_system_config_serialization() {
        let config = SystemConfig::new(98765432109876, 12345678901234);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SystemConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }
}
