//! Shared types for Control API responses

use serde::{Deserialize, Serialize};

/// Organization information from Control
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrganizationInfo {
    /// Organization Snowflake ID
    pub id: i64,
    /// Organization name
    pub name: String,
    /// Organization status
    pub status: OrgStatus,
}

/// Organization status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OrgStatus {
    /// Organization is active
    Active,
    /// Organization is suspended
    Suspended,
    /// Organization is deleted
    Deleted,
}

/// Vault information from Control
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultInfo {
    /// Vault Snowflake ID
    pub id: i64,
    /// Vault name
    pub name: String,
    /// Organization Snowflake ID that owns this vault
    pub organization_id: i64,
}
