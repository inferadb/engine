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
