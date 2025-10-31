//! # Infera Types
//!
//! Shared type definitions for the InferaDB authorization system.
//!
//! This crate provides all core types used across the InferaDB ecosystem,
//! ensuring a single source of truth and preventing circular dependencies.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Core Domain Types
// ============================================================================

/// A relationship representing an authorization relationship between a subject and resource
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Relationship {
    pub resource: String,
    pub relation: String,
    pub subject: String,
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
pub enum Decision {
    Allow,
    Deny,
}

// ============================================================================
// Request/Response Types - Evaluate
// ============================================================================

/// A permission evaluation request
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    ComputedUserset {
        relation: String,
    },
    RelatedObjectUserset {
        relationship: String,
        computed: String,
    },
    Union,
    Intersection,
    Exclusion,
    Leaf {
        users: Vec<String>,
    },
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    pub fn exact(resource: String, relation: String, subject: String) -> Self {
        Self {
            resource: Some(resource),
            relation: Some(relation),
            subject: Some(subject),
        }
    }

    /// Create a filter for all relationships of a resource
    pub fn by_resource(resource: String) -> Self {
        Self {
            resource: Some(resource),
            relation: None,
            subject: None,
        }
    }

    /// Create a filter for all relationships of a subject (user offboarding)
    pub fn by_subject(subject: String) -> Self {
        Self {
            resource: None,
            relation: None,
            subject: Some(subject),
        }
    }

    /// Create a filter by resource and relation
    pub fn by_resource_relation(resource: String, relation: String) -> Self {
        Self {
            resource: Some(resource),
            relation: Some(relation),
            subject: None,
        }
    }
}

/// Request to delete relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        Self {
            filter: None,
            relationships: Some(relationships),
            limit: None,
        }
    }

    /// Create request to delete by filter
    pub fn by_filter(filter: DeleteFilter) -> Self {
        Self {
            filter: Some(filter),
            relationships: None,
            limit: None,
        }
    }

    /// Create request to delete by filter with limit
    pub fn by_filter_limited(filter: DeleteFilter, limit: usize) -> Self {
        Self {
            filter: Some(filter),
            relationships: None,
            limit: Some(limit),
        }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
