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
// Request/Response Types - Check
// ============================================================================

/// A permission check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRequest {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub context: Option<serde_json::Value>,
}

/// Response from a check operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResponse {
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

/// Request to delete relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub relationships: Vec<Relationship>,
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
    pub checks: Vec<CheckRequest>,
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
