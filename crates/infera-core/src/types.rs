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
