//! # Infera Repl - Replication and Consistency Management
//!
//! Handles replication, revision tokens, and consistency management.

use thiserror::Error;

pub mod agent;
pub mod change_feed;
pub mod conflict;
pub mod router;
pub mod snapshot;
pub mod token;
pub mod topology;

pub use agent::{ReplicationAgent, ReplicationConfig, ReplicationStats};
pub use change_feed::{
    Change, ChangeFeed, ChangeFeedConfig, ChangeFilter, ChangeMetadata, ChangeStream, Operation,
};
pub use conflict::{
    Conflict, ConflictResolutionStrategy, ConflictResolver, ConflictStats, Resolution,
};
pub use router::{RequestType, Router, RoutingDecision};
pub use token::RevisionToken;
pub use topology::{
    Node, NodeId, NodeStatus, Region, RegionId, ReplicationStrategy, Topology, TopologyBuilder,
    TopologyError, Zone, ZoneId,
};

#[derive(Debug, Error)]
pub enum ReplError {
    #[error("Conflict detected")]
    Conflict,

    #[error("Invalid revision token")]
    InvalidRevision,

    #[error("Replication error: {0}")]
    Replication(String),

    #[error("Store error: {0}")]
    Store(#[from] infera_store::StoreError),
}

pub type Result<T> = std::result::Result<T, ReplError>;
