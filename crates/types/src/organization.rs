//! Organization type
//!
//! Represents an organization that owns Vaults in InferaDB's multi-tenant system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An Organization that owns one or more Vaults.
///
/// Organizations are the top-level ownership entity in InferaDB's multi-tenancy model.
/// Each Organization can own zero, one, or many Vaults, providing isolation boundaries
/// for authorization data.
/// IDs are Snowflake IDs (i64) from the Management API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    /// Unique identifier for this organization (Snowflake ID from Management API)
    pub id: i64,

    /// Human-readable name for the organization
    pub name: String,

    /// When this organization was created
    pub created_at: DateTime<Utc>,

    /// When this organization was last updated
    pub updated_at: DateTime<Utc>,
}

impl Organization {
    /// Create a new Organization with a specific ID
    pub fn new(id: i64, name: String) -> Self {
        let now = Utc::now();
        Self { id, name, created_at: now, updated_at: now }
    }

    /// Create an Organization with a specific ID (alias for new)
    pub fn with_id(id: i64, name: String) -> Self {
        Self::new(id, name)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_new() {
        let id: i64 = 98765432109876;
        let organization = Organization::new(id, "Test Organization".to_string());
        assert_eq!(organization.id, id);
        assert_eq!(organization.name, "Test Organization");
        assert!(organization.created_at <= Utc::now());
        assert_eq!(organization.created_at, organization.updated_at);
    }

    #[test]
    fn test_organization_with_id() {
        let id: i64 = 98765432109876;
        let organization = Organization::with_id(id, "Test Organization".to_string());
        assert_eq!(organization.id, id);
        assert_eq!(organization.name, "Test Organization");
    }

    #[test]
    fn test_organization_serialization() {
        let id: i64 = 98765432109876;
        let organization = Organization::new(id, "Test Organization".to_string());
        let json = serde_json::to_string(&organization).unwrap();
        let deserialized: Organization = serde_json::from_str(&json).unwrap();
        assert_eq!(organization, deserialized);
    }
}
