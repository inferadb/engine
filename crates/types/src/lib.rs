//! # Infera Types
//!
//! Shared type definitions for the InferaDB authorization system.
//!
//! This crate provides all core types used across the InferaDB ecosystem,
//! ensuring a single source of truth and preventing circular dependencies.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Multi-Tenancy Types
// ============================================================================

pub mod organization;
pub mod vault;

pub use organization::Organization;
pub use vault::{SystemConfig, Vault};

// ============================================================================
// Authentication Types
// ============================================================================

pub mod auth;

pub use auth::{AuthContext, AuthMethod};

// ============================================================================
// Core Domain Types
// ============================================================================

/// A relationship representing an authorization relationship between a subject and resource
///
/// All relationships are scoped to a specific Vault for multi-tenant isolation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Relationship {
    /// The vault this relationship belongs to (Snowflake ID from Management API)
    /// During deserialization (e.g., from API requests), this defaults to 0
    /// and should be set by the API layer based on authentication context
    #[serde(default)]
    pub vault: i64,
    pub resource: String,
    pub relation: String,
    pub subject: String,
}

impl Relationship {
    /// Check if the subject is a wildcard (e.g., "user:*")
    pub fn is_wildcard_subject(&self) -> bool {
        self.subject.ends_with(":*")
    }

    /// Get the subject type from a subject string (e.g., "user" from "user:alice" or "user:*")
    pub fn subject_type(&self) -> Option<&str> {
        self.subject.split(':').next()
    }

    /// Get the subject ID from a subject string (e.g., "alice" from "user:alice", or "*" from
    /// "user:*")
    pub fn subject_id(&self) -> Option<&str> {
        self.subject.split(':').nth(1)
    }

    /// Check if this relationship would match a specific subject
    /// Returns true if:
    /// 1. The subject exactly matches, OR
    /// 2. This is a wildcard relationship and the subject type matches
    pub fn matches_subject(&self, subject: &str) -> bool {
        if self.subject == subject {
            return true;
        }

        if self.is_wildcard_subject() {
            // Extract type from both wildcard and subject
            if let (Some(wildcard_type), Some(subject_type)) =
                (self.subject.split(':').next(), subject.split(':').next())
            {
                return wildcard_type == subject_type;
            }
        }

        false
    }

    /// Validate that wildcards are only used in the subject position
    /// Returns an error if wildcards are found in resource or relation
    pub fn validate_wildcard_placement(&self) -> std::result::Result<(), String> {
        if self.resource.contains('*') {
            return Err("Wildcards are not allowed in resource field".to_string());
        }
        if self.relation.contains('*') {
            return Err("Wildcards are not allowed in relation field".to_string());
        }
        if self.subject.contains('*') && !self.subject.ends_with(":*") {
            return Err("Wildcards in subject must be in the format 'type:*'".to_string());
        }
        Ok(())
    }
}

/// A relationship key for lookups (subject is optional for partial matching)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelationshipKey {
    pub resource: String,
    pub relation: String,
    pub subject: Option<String>,
}

/// A revision/version token for consistent reads
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Revision(pub u64);

impl Revision {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Not found")]
    NotFound,

    #[error("Conflict")]
    Conflict,

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;

// ============================================================================
// Decision Types
// ============================================================================

/// The result of a permission check
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

// ============================================================================
// Request/Response Types - Evaluate
// ============================================================================

/// A permission evaluation request
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct EvaluateRequest {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub context: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<bool>,
}

/// Response from an evaluation operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub decision: Decision,
}

// ============================================================================
// Request/Response Types - Expand
// ============================================================================

/// A request to expand a permission into its constituent relationships
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct ExpandRequest {
    pub resource: String,
    pub relation: String,
    /// Optional limit on number of users to return (default: no limit)
    pub limit: Option<usize>,
    /// Optional continuation token from previous request
    pub continuation_token: Option<String>,
}

/// Response from an expand operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpandResponse {
    /// The userset tree showing the structure
    pub tree: UsersetTree,
    /// All users in the expanded set (deduplicated)
    pub users: Vec<String>,
    /// Continuation token for paginated results (if more results available)
    pub continuation_token: Option<String>,
    /// Total number of users (may be approximate if paginated)
    pub total_count: Option<usize>,
}

/// A tree representing the expanded userset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersetTree {
    pub node_type: UsersetNodeType,
    pub children: Vec<UsersetTree>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsersetNodeType {
    This,
    ComputedUserset { relation: String },
    RelatedObjectUserset { relationship: String, computed: String },
    Union,
    Intersection,
    Exclusion,
    Leaf { users: Vec<String> },
}

// ============================================================================
// Request/Response Types - Write
// ============================================================================

/// Request to write relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    pub relationships: Vec<Relationship>,
}

/// Response from a write operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResponse {
    pub revision: Revision,
    pub relationships_written: usize,
}

// ============================================================================
// Request/Response Types - Delete
// ============================================================================

/// Filter for deleting relationships
/// All fields are optional and can be combined.
/// If all fields are None, this is an error (would delete everything).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, bon::Builder)]
#[builder(on(String, into))]
pub struct DeleteFilter {
    /// Filter by resource (e.g., "doc:readme")
    /// Exact match only
    pub resource: Option<String>,
    /// Filter by relation (e.g., "viewer")
    /// Exact match only
    pub relation: Option<String>,
    /// Filter by subject (e.g., "user:alice")
    /// Exact match only
    pub subject: Option<String>,
}

impl DeleteFilter {
    /// Returns true if all fields are None (invalid filter)
    pub fn is_empty(&self) -> bool {
        self.resource.is_none() && self.relation.is_none() && self.subject.is_none()
    }

    /// Create a filter for an exact relationship
    pub fn exact(
        resource: impl Into<String>,
        relation: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        Self::builder().resource(resource).relation(relation).subject(subject).build()
    }

    /// Create a filter for all relationships of a resource
    pub fn by_resource(resource: impl Into<String>) -> Self {
        Self::builder().resource(resource).build()
    }

    /// Create a filter for all relationships of a subject (user offboarding)
    pub fn by_subject(subject: impl Into<String>) -> Self {
        Self::builder().subject(subject).build()
    }

    /// Create a filter by resource and relation
    pub fn by_resource_relation(resource: impl Into<String>, relation: impl Into<String>) -> Self {
        Self::builder().resource(resource).relation(relation).build()
    }
}

/// Request to delete relationships
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
pub struct DeleteRequest {
    /// Optional filter for bulk deletion
    /// If provided, all relationships matching the filter will be deleted
    pub filter: Option<DeleteFilter>,
    /// Optional exact relationships to delete
    /// If provided along with filter, both will be processed
    pub relationships: Option<Vec<Relationship>>,
    /// Maximum number of relationships to delete (safety limit)
    /// If not specified, uses a default limit
    /// Set to 0 for unlimited (use with caution!)
    pub limit: Option<usize>,
}

impl DeleteRequest {
    /// Create request to delete exact relationships
    pub fn exact(relationships: Vec<Relationship>) -> Self {
        Self::builder().relationships(relationships).build()
    }

    /// Create request to delete by filter
    pub fn by_filter(filter: DeleteFilter) -> Self {
        Self::builder().filter(filter).build()
    }

    /// Create request to delete by filter with limit
    pub fn by_filter_limited(filter: DeleteFilter, limit: usize) -> Self {
        Self::builder().filter(filter).limit(limit).build()
    }
}

/// Response from a delete operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub revision: Revision,
    pub relationships_deleted: usize,
}

// ============================================================================
// Request/Response Types - Batch Simulate
// ============================================================================

/// A request to simulate changes to the authorization graph (batch mode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSimulateRequest {
    pub checks: Vec<EvaluateRequest>,
    pub context_relationships: Vec<Relationship>,
}

/// Response from a batch simulate operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSimulateResponse {
    pub results: Vec<Decision>,
}

// ============================================================================
// Request/Response Types - List Resources
// ============================================================================

/// A request to list resources accessible by a subject
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct ListResourcesRequest {
    /// Subject (e.g., "user:alice")
    pub subject: String,
    /// Resource type to filter by (e.g., "document")
    pub resource_type: String,
    /// Permission to check (e.g., "can_view")
    pub permission: String,
    /// Optional limit on number of resources to return
    pub limit: Option<usize>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
    /// Optional resource ID pattern filter (supports wildcards: * and ?)
    /// Examples: "doc:readme*", "user:alice_?", "folder:*/subfolder"
    pub resource_id_pattern: Option<String>,
}

/// Response from a list resources operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResourcesResponse {
    /// List of accessible resources
    pub resources: Vec<String>,
    /// Continuation token for pagination (if more results available)
    pub cursor: Option<String>,
    /// Total count estimate (may be approximate if paginated)
    pub total_count: Option<usize>,
}

// ============================================================================
// Request/Response Types - List Relationships
// ============================================================================

/// A request to list relationships with optional filtering
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct ListRelationshipsRequest {
    /// Optional filter by resource (e.g., "doc:readme")
    pub resource: Option<String>,
    /// Optional filter by relation (e.g., "viewer")
    pub relation: Option<String>,
    /// Optional filter by subject (e.g., "user:alice")
    pub subject: Option<String>,
    /// Optional limit on number of relationships to return (default: 100, max: 1000)
    pub limit: Option<usize>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
}

/// Response from a list relationships operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRelationshipsResponse {
    /// List of relationships matching the filter
    pub relationships: Vec<Relationship>,
    /// Continuation token for pagination (if more results available)
    pub cursor: Option<String>,
    /// Total count of relationships returned
    pub total_count: Option<usize>,
}

// ============================================================================
// Request/Response Types - List Subjects
// ============================================================================

/// A request to list subjects that have a relation to a resource
#[derive(Debug, Clone, Serialize, Deserialize, bon::Builder)]
#[builder(on(String, into))]
pub struct ListSubjectsRequest {
    /// Resource (e.g., "document:readme")
    pub resource: String,
    /// Relation to check (e.g., "viewer")
    pub relation: String,
    /// Optional filter by subject type (e.g., "user", "group")
    pub subject_type: Option<String>,
    /// Optional limit on number of subjects to return
    pub limit: Option<usize>,
    /// Optional continuation token from previous request
    pub cursor: Option<String>,
}

/// Response from a list subjects operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSubjectsResponse {
    /// List of subjects with the relation to the resource
    pub subjects: Vec<String>,
    /// Continuation token for pagination (if more results available)
    pub cursor: Option<String>,
    /// Total count estimate (may be approximate if paginated)
    pub total_count: Option<usize>,
}

// ============================================================================
// Request/Response Types - Organization Management
// ============================================================================

/// Request to create a new organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    /// Organization name (must be non-empty, max 255 characters)
    pub name: String,
}

/// Request to update an existing organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOrganizationRequest {
    /// New organization name (must be non-empty, max 255 characters)
    pub name: String,
}

/// Organization response with full details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationResponse {
    pub id: i64,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Response containing a list of organizations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListOrganizationsResponse {
    pub organizations: Vec<OrganizationResponse>,
}

// ============================================================================
// Request/Response Types - Vault Management
// ============================================================================

/// Request to create a new vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    /// Vault name (must be non-empty, max 255 characters)
    pub name: String,
}

/// Request to update an existing vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateVaultRequest {
    /// Optional new vault name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional new organization owner (admin only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<i64>,
}

/// Vault response with full details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultResponse {
    pub id: i64,
    pub organization: i64,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Response containing a list of vaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListVaultsResponse {
    pub vaults: Vec<VaultResponse>,
}

impl From<Organization> for OrganizationResponse {
    fn from(organization: Organization) -> Self {
        Self {
            id: organization.id,
            name: organization.name,
            created_at: organization.created_at,
            updated_at: organization.updated_at,
        }
    }
}

impl From<Vault> for VaultResponse {
    fn from(vault: Vault) -> Self {
        Self {
            id: vault.id,
            organization: vault.organization,
            name: vault.name,
            created_at: vault.created_at,
            updated_at: vault.updated_at,
        }
    }
}

// ============================================================================
// Request/Response Types - Watch
// ============================================================================

/// Type of change operation for Watch API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeOperation {
    /// Relationship was created
    Create,
    /// Relationship was deleted
    Delete,
}

/// A change event representing a relationship change
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeEvent {
    /// Type of change operation
    pub operation: ChangeOperation,
    /// The relationship that changed
    pub relationship: Relationship,
    /// Revision at which this change occurred
    pub revision: Revision,
    /// Timestamp when the change occurred (Unix timestamp in nanoseconds)
    pub timestamp_nanos: i64,
}

impl ChangeEvent {
    /// Create a new change event for a relationship creation
    pub fn create(relationship: Relationship, revision: Revision, timestamp_nanos: i64) -> Self {
        Self { operation: ChangeOperation::Create, relationship, revision, timestamp_nanos }
    }

    /// Create a new change event for a relationship deletion
    pub fn delete(relationship: Relationship, revision: Revision, timestamp_nanos: i64) -> Self {
        Self { operation: ChangeOperation::Delete, relationship, revision, timestamp_nanos }
    }

    /// Get the resource type from this change event
    pub fn resource_type(&self) -> Option<&str> {
        self.relationship.resource.split(':').next()
    }
}

/// Request to watch for relationship changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRequest {
    /// Optional filter by resource types (e.g., ["document", "folder"])
    /// If empty, watches all relationship changes
    pub resource_types: Vec<String>,
    /// Optional start cursor/revision to resume from
    /// If None, starts from current point in time
    pub cursor: Option<String>,
}

/// Response from a watch operation (single change event)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchResponse {
    /// Type of change operation
    pub operation: ChangeOperation,
    /// The relationship that changed
    pub relationship: Relationship,
    /// Revision at which this change occurred
    pub revision: String,
    /// Timestamp in ISO 8601 format
    pub timestamp: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wildcard_subject() {
        let wildcard = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:*".to_string(),
        };
        assert!(wildcard.is_wildcard_subject());

        let normal = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        assert!(!normal.is_wildcard_subject());
    }

    #[test]
    fn test_subject_type() {
        let rel = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        assert_eq!(rel.subject_type(), Some("user"));

        let wildcard = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "group:*".to_string(),
        };
        assert_eq!(wildcard.subject_type(), Some("group"));
    }

    #[test]
    fn test_subject_id() {
        let rel = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        assert_eq!(rel.subject_id(), Some("alice"));

        let wildcard = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:*".to_string(),
        };
        assert_eq!(wildcard.subject_id(), Some("*"));
    }

    #[test]
    fn test_matches_subject() {
        let wildcard = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:*".to_string(),
        };

        // Wildcard should match any user
        assert!(wildcard.matches_subject("user:alice"));
        assert!(wildcard.matches_subject("user:bob"));
        assert!(wildcard.matches_subject("user:charlie"));

        // Wildcard should NOT match different type
        assert!(!wildcard.matches_subject("group:admins"));

        // Exact match should work
        let exact = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        assert!(exact.matches_subject("user:alice"));
        assert!(!exact.matches_subject("user:bob"));
    }

    #[test]
    fn test_validate_wildcard_placement() {
        // Valid: wildcard in subject
        let valid = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:*".to_string(),
        };
        assert!(valid.validate_wildcard_placement().is_ok());

        // Valid: no wildcard
        let valid_no_wildcard = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        assert!(valid_no_wildcard.validate_wildcard_placement().is_ok());

        // Invalid: wildcard in resource
        let invalid_resource = Relationship {
            vault: 0,
            resource: "doc:*".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        assert!(invalid_resource.validate_wildcard_placement().is_err());

        // Invalid: wildcard in relation
        let invalid_relation = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "view*".to_string(),
            subject: "user:alice".to_string(),
        };
        assert!(invalid_relation.validate_wildcard_placement().is_err());

        // Invalid: wildcard not at end of subject
        let invalid_subject_position = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:*:subgroup".to_string(),
        };
        assert!(invalid_subject_position.validate_wildcard_placement().is_err());
    }

    #[test]
    fn test_wildcard_with_different_types() {
        let group_wildcard = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "group:*".to_string(),
        };

        assert!(group_wildcard.matches_subject("group:admins"));
        assert!(group_wildcard.matches_subject("group:engineers"));
        assert!(!group_wildcard.matches_subject("user:alice"));
    }

    #[test]
    fn test_delete_filter_helpers() {
        let exact = DeleteFilter::exact(
            "doc:readme".to_string(),
            "viewer".to_string(),
            "user:alice".to_string(),
        );
        assert!(!exact.is_empty());
        assert_eq!(exact.resource, Some("doc:readme".to_string()));
        assert_eq!(exact.relation, Some("viewer".to_string()));
        assert_eq!(exact.subject, Some("user:alice".to_string()));

        let by_resource = DeleteFilter::by_resource("doc:readme".to_string());
        assert!(!by_resource.is_empty());
        assert_eq!(by_resource.resource, Some("doc:readme".to_string()));
        assert_eq!(by_resource.relation, None);
        assert_eq!(by_resource.subject, None);
    }

    // =========================================================================
    // Request Builder API Tests (TDD for bon::Builder adoption)
    // =========================================================================

    #[test]
    fn test_evaluate_request_builder() {
        let req = EvaluateRequest::builder()
            .subject("user:alice")
            .resource("doc:readme")
            .permission("read")
            .build();
        assert_eq!(req.subject, "user:alice");
        assert_eq!(req.resource, "doc:readme");
        assert_eq!(req.permission, "read");
        assert!(req.context.is_none());
        assert!(req.trace.is_none());
    }

    #[test]
    fn test_evaluate_request_builder_with_optional_fields() {
        let context = serde_json::json!({"ip": "192.168.1.1"});
        let req = EvaluateRequest::builder()
            .subject("user:bob")
            .resource("folder:docs")
            .permission("write")
            .context(context.clone())
            .trace(true)
            .build();
        assert_eq!(req.context, Some(context));
        assert_eq!(req.trace, Some(true));
    }

    #[test]
    fn test_expand_request_builder() {
        let req = ExpandRequest::builder().resource("doc:readme").relation("viewer").build();
        assert_eq!(req.resource, "doc:readme");
        assert_eq!(req.relation, "viewer");
        assert!(req.limit.is_none());
        assert!(req.continuation_token.is_none());
    }

    #[test]
    fn test_expand_request_builder_with_pagination() {
        let req = ExpandRequest::builder()
            .resource("folder:shared")
            .relation("owner")
            .limit(100)
            .continuation_token("token123")
            .build();
        assert_eq!(req.limit, Some(100));
        assert_eq!(req.continuation_token, Some("token123".to_string()));
    }

    #[test]
    fn test_list_resources_request_builder() {
        let req = ListResourcesRequest::builder()
            .subject("user:alice")
            .resource_type("document")
            .permission("can_view")
            .build();
        assert_eq!(req.subject, "user:alice");
        assert_eq!(req.resource_type, "document");
        assert_eq!(req.permission, "can_view");
        assert!(req.limit.is_none());
        assert!(req.cursor.is_none());
        assert!(req.resource_id_pattern.is_none());
    }

    #[test]
    fn test_list_resources_request_builder_with_pagination() {
        let req = ListResourcesRequest::builder()
            .subject("user:bob")
            .resource_type("folder")
            .permission("can_edit")
            .limit(50)
            .cursor("cursor123")
            .resource_id_pattern("folder:docs*")
            .build();
        assert_eq!(req.limit, Some(50));
        assert_eq!(req.cursor, Some("cursor123".to_string()));
        assert_eq!(req.resource_id_pattern, Some("folder:docs*".to_string()));
    }

    #[test]
    fn test_list_relationships_request_builder() {
        // All fields are optional for ListRelationshipsRequest
        let req = ListRelationshipsRequest::builder().build();
        assert!(req.resource.is_none());
        assert!(req.relation.is_none());
        assert!(req.subject.is_none());
        assert!(req.limit.is_none());
        assert!(req.cursor.is_none());
    }

    #[test]
    fn test_list_relationships_request_builder_with_filters() {
        let req = ListRelationshipsRequest::builder()
            .resource("doc:readme")
            .relation("viewer")
            .subject("user:alice")
            .limit(100)
            .cursor("page2")
            .build();
        assert_eq!(req.resource, Some("doc:readme".to_string()));
        assert_eq!(req.relation, Some("viewer".to_string()));
        assert_eq!(req.subject, Some("user:alice".to_string()));
        assert_eq!(req.limit, Some(100));
        assert_eq!(req.cursor, Some("page2".to_string()));
    }

    #[test]
    fn test_list_subjects_request_builder() {
        let req =
            ListSubjectsRequest::builder().resource("document:readme").relation("viewer").build();
        assert_eq!(req.resource, "document:readme");
        assert_eq!(req.relation, "viewer");
        assert!(req.subject_type.is_none());
        assert!(req.limit.is_none());
        assert!(req.cursor.is_none());
    }

    #[test]
    fn test_list_subjects_request_builder_with_filters() {
        let req = ListSubjectsRequest::builder()
            .resource("folder:shared")
            .relation("owner")
            .subject_type("user")
            .limit(25)
            .cursor("next_page")
            .build();
        assert_eq!(req.subject_type, Some("user".to_string()));
        assert_eq!(req.limit, Some(25));
        assert_eq!(req.cursor, Some("next_page".to_string()));
    }

    #[test]
    fn test_delete_filter_builder() {
        let filter = DeleteFilter::builder()
            .resource("doc:readme")
            .relation("viewer")
            .subject("user:alice")
            .build();
        assert_eq!(filter.resource, Some("doc:readme".to_string()));
        assert_eq!(filter.relation, Some("viewer".to_string()));
        assert_eq!(filter.subject, Some("user:alice".to_string()));
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_delete_filter_builder_partial() {
        // Builder allows partial filters (unlike the factory methods)
        let filter = DeleteFilter::builder().resource("doc:readme").build();
        assert_eq!(filter.resource, Some("doc:readme".to_string()));
        assert!(filter.relation.is_none());
        assert!(filter.subject.is_none());
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_delete_filter_factory_methods_use_builder() {
        // Verify factory methods still work with impl Into<String>
        let exact = DeleteFilter::exact("doc:readme", "viewer", "user:alice");
        assert_eq!(exact.resource, Some("doc:readme".to_string()));
        assert_eq!(exact.relation, Some("viewer".to_string()));
        assert_eq!(exact.subject, Some("user:alice".to_string()));

        let by_resource = DeleteFilter::by_resource("doc:readme");
        assert_eq!(by_resource.resource, Some("doc:readme".to_string()));

        let by_subject = DeleteFilter::by_subject("user:alice");
        assert_eq!(by_subject.subject, Some("user:alice".to_string()));

        let by_resource_relation = DeleteFilter::by_resource_relation("doc:readme", "viewer");
        assert_eq!(by_resource_relation.resource, Some("doc:readme".to_string()));
        assert_eq!(by_resource_relation.relation, Some("viewer".to_string()));
    }

    #[test]
    fn test_delete_request_builder() {
        let filter = DeleteFilter::by_subject("user:alice");
        let req = DeleteRequest::builder().filter(filter.clone()).limit(100).build();
        assert_eq!(req.filter, Some(filter));
        assert!(req.relationships.is_none());
        assert_eq!(req.limit, Some(100));
    }

    #[test]
    fn test_delete_request_builder_with_relationships() {
        let relationships = vec![Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        }];
        let req = DeleteRequest::builder().relationships(relationships.clone()).build();
        assert!(req.filter.is_none());
        assert_eq!(req.relationships, Some(relationships));
    }

    #[test]
    fn test_delete_request_factory_methods() {
        let relationships = vec![Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        }];
        let req = DeleteRequest::exact(relationships.clone());
        assert_eq!(req.relationships, Some(relationships));

        let filter = DeleteFilter::by_resource("doc:readme".to_string());
        let req2 = DeleteRequest::by_filter(filter.clone());
        assert_eq!(req2.filter, Some(filter.clone()));

        let req3 = DeleteRequest::by_filter_limited(filter.clone(), 50);
        assert_eq!(req3.filter, Some(filter));
        assert_eq!(req3.limit, Some(50));
    }
}
