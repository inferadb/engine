//! Core types for authorization checks and policy evaluation

use serde::{Deserialize, Serialize};

/// A permission check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRequest {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub context: Option<serde_json::Value>,
}

/// The result of a permission check
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

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
    ComputedUserset { relation: String },
    TupleToUserset { tupleset: String, computed: String },
    Union,
    Intersection,
    Exclusion,
    Leaf { users: Vec<String> },
}

/// A request to simulate changes to the authorization graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateRequest {
    pub checks: Vec<CheckRequest>,
    pub context_tuples: Vec<Tuple>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateResponse {
    pub results: Vec<Decision>,
}

/// A tuple representing a relationship
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub object: String,
    pub relation: String,
    pub user: String,
}

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

/// Relationship represents an authorization relationship with API-friendly naming.
/// This is the API-level representation, separate from the storage-level Tuple.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Relationship {
    /// Resource identifier (e.g., "doc:readme")
    pub resource: String,
    /// Relation type (e.g., "viewer", "editor")
    pub relation: String,
    /// Subject identifier (e.g., "user:alice", "group:engineers")
    pub subject: String,
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
