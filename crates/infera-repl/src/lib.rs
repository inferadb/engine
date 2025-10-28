//! # Infera Repl - Replication and Consistency Management
//!
//! Handles replication, revision tokens, and consistency management.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod token;
pub mod snapshot;

pub use token::RevisionToken;

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

/// Change feed for replication
pub struct ChangeFeed {
    // TODO: Implement change feed with NATS/Kafka
}

impl ChangeFeed {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn publish(&self, _change: Change) -> Result<()> {
        // TODO: Implement
        Ok(())
    }

    pub async fn subscribe(&self) -> Result<ChangeStream> {
        // TODO: Implement
        Ok(ChangeStream {})
    }
}

impl Default for ChangeFeed {
    fn default() -> Self {
        Self::new()
    }
}

/// A change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub revision: u64,
    pub operation: Operation,
    pub tuple: infera_store::Tuple,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    Insert,
    Delete,
}

/// Stream of changes
pub struct ChangeStream {
    // TODO: Implement
}
