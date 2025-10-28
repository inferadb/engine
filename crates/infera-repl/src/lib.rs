//! # Infera Repl - Replication and Consistency Management
//!
//! Handles replication, revision tokens, and consistency management.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReplError {
    #[error("Conflict detected")]
    Conflict,

    #[error("Invalid revision token")]
    InvalidRevision,

    #[error("Replication error: {0}")]
    Replication(String),
}

pub type Result<T> = std::result::Result<T, ReplError>;

/// A zookie-style revision token for snapshot consistency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevisionToken {
    pub node_id: String,
    pub revision: u64,
    pub vector_clock: Vec<(String, u64)>,
}

impl RevisionToken {
    pub fn new(node_id: String, revision: u64) -> Self {
        Self {
            node_id: node_id.clone(),
            revision,
            vector_clock: vec![(node_id, revision)],
        }
    }

    /// Check if this token is causally after another
    pub fn is_after(&self, other: &RevisionToken) -> bool {
        for (node, clock) in &other.vector_clock {
            let our_clock = self.vector_clock.iter()
                .find(|(n, _)| n == node)
                .map(|(_, c)| c)
                .unwrap_or(&0);

            if our_clock < clock {
                return false;
            }
        }
        true
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revision_token_causality() {
        let token1 = RevisionToken::new("node1".to_string(), 1);
        let token2 = RevisionToken::new("node1".to_string(), 2);

        assert!(!token1.is_after(&token2));
        assert!(token2.is_after(&token1));
    }
}
