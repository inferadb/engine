//! Revision token generation and validation
//!
//! Implements "zookie"-style revision tokens for snapshot consistency

use crate::{ReplError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A zookie-style revision token for snapshot consistency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevisionToken {
    /// Node ID that generated this token
    pub node_id: String,
    /// Revision number at this node
    pub revision: u64,
    /// Vector clock for causal ordering
    pub vector_clock: HashMap<String, u64>,
}

impl RevisionToken {
    /// Create a new revision token for a single node
    pub fn new(node_id: String, revision: u64) -> Self {
        let mut vector_clock = HashMap::new();
        vector_clock.insert(node_id.clone(), revision);

        Self {
            node_id,
            revision,
            vector_clock,
        }
    }

    /// Create a revision token with a specific vector clock
    pub fn with_vector_clock(
        node_id: String,
        revision: u64,
        vector_clock: HashMap<String, u64>,
    ) -> Self {
        Self {
            node_id,
            revision,
            vector_clock,
        }
    }

    /// Check if this token is causally after another token
    /// Returns true if this token happens-after the other token
    pub fn is_after(&self, other: &RevisionToken) -> bool {
        // For every entry in other's vector clock, our clock must be >=
        for (node, other_clock) in &other.vector_clock {
            let our_clock = self.vector_clock.get(node).copied().unwrap_or(0);
            if our_clock < *other_clock {
                return false;
            }
        }

        // Additionally, at least one entry must be strictly greater
        let any_greater = other.vector_clock.iter().any(|(node, other_clock)| {
            let our_clock = self.vector_clock.get(node).copied().unwrap_or(0);
            our_clock > *other_clock
        });

        any_greater
    }

    /// Check if this token is causally before another token
    pub fn is_before(&self, other: &RevisionToken) -> bool {
        other.is_after(self)
    }

    /// Check if two tokens are concurrent (neither is before the other)
    pub fn is_concurrent_with(&self, other: &RevisionToken) -> bool {
        !self.is_after(other) && !self.is_before(other)
    }

    /// Merge two revision tokens (used in replication)
    /// Creates a token that is causally after both inputs
    pub fn merge(&self, other: &RevisionToken) -> RevisionToken {
        let mut merged_clock = self.vector_clock.clone();

        for (node, other_rev) in &other.vector_clock {
            merged_clock
                .entry(node.clone())
                .and_modify(|rev| *rev = (*rev).max(*other_rev))
                .or_insert(*other_rev);
        }

        // Use the current node's ID and revision
        RevisionToken {
            node_id: self.node_id.clone(),
            revision: self.revision,
            vector_clock: merged_clock,
        }
    }

    /// Serialize to base64-encoded JSON string
    pub fn encode(&self) -> Result<String> {
        use base64::Engine;
        let json = serde_json::to_string(self)
            .map_err(|e| ReplError::Replication(format!("Failed to serialize token: {}", e)))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(json))
    }

    /// Deserialize from base64-encoded JSON string
    pub fn decode(encoded: &str) -> Result<Self> {
        use base64::Engine;
        let json = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_e| ReplError::InvalidRevision)?;
        let json_str = String::from_utf8(json).map_err(|_e| ReplError::InvalidRevision)?;
        serde_json::from_str(&json_str).map_err(|_e| ReplError::InvalidRevision)
    }

    /// Validate the token format
    pub fn validate(&self) -> Result<()> {
        // Node ID must not be empty
        if self.node_id.is_empty() {
            return Err(ReplError::InvalidRevision);
        }

        // Revision must be > 0
        if self.revision == 0 {
            return Err(ReplError::InvalidRevision);
        }

        // Vector clock must not be empty
        if self.vector_clock.is_empty() {
            return Err(ReplError::InvalidRevision);
        }

        // Vector clock must include this node
        if !self.vector_clock.contains_key(&self.node_id) {
            return Err(ReplError::InvalidRevision);
        }

        // This node's clock should match the revision
        if self.vector_clock.get(&self.node_id) != Some(&self.revision) {
            return Err(ReplError::InvalidRevision);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_token() {
        let token = RevisionToken::new("node1".to_string(), 5);

        assert_eq!(token.node_id, "node1");
        assert_eq!(token.revision, 5);
        assert_eq!(token.vector_clock.len(), 1);
        assert_eq!(token.vector_clock.get("node1"), Some(&5));
    }

    #[test]
    fn test_causality_simple() {
        let token1 = RevisionToken::new("node1".to_string(), 1);
        let token2 = RevisionToken::new("node1".to_string(), 2);

        assert!(!token1.is_after(&token2));
        assert!(token2.is_after(&token1));
        assert!(token1.is_before(&token2));
        assert!(!token2.is_before(&token1));
    }

    #[test]
    fn test_causality_multi_node() {
        let mut clock1 = HashMap::new();
        clock1.insert("node1".to_string(), 1);
        clock1.insert("node2".to_string(), 1);
        let token1 = RevisionToken::with_vector_clock("node1".to_string(), 1, clock1);

        let mut clock2 = HashMap::new();
        clock2.insert("node1".to_string(), 2);
        clock2.insert("node2".to_string(), 1);
        let token2 = RevisionToken::with_vector_clock("node1".to_string(), 2, clock2);

        assert!(token2.is_after(&token1));
        assert!(!token1.is_after(&token2));
    }

    #[test]
    fn test_concurrent_tokens() {
        let mut clock1 = HashMap::new();
        clock1.insert("node1".to_string(), 2);
        clock1.insert("node2".to_string(), 1);
        let token1 = RevisionToken::with_vector_clock("node1".to_string(), 2, clock1);

        let mut clock2 = HashMap::new();
        clock2.insert("node1".to_string(), 1);
        clock2.insert("node2".to_string(), 2);
        let token2 = RevisionToken::with_vector_clock("node2".to_string(), 2, clock2);

        assert!(token1.is_concurrent_with(&token2));
        assert!(token2.is_concurrent_with(&token1));
        assert!(!token1.is_after(&token2));
        assert!(!token2.is_after(&token1));
    }

    #[test]
    fn test_merge_tokens() {
        let mut clock1 = HashMap::new();
        clock1.insert("node1".to_string(), 2);
        clock1.insert("node2".to_string(), 1);
        let token1 = RevisionToken::with_vector_clock("node1".to_string(), 2, clock1);

        let mut clock2 = HashMap::new();
        clock2.insert("node1".to_string(), 1);
        clock2.insert("node2".to_string(), 3);
        let token2 = RevisionToken::with_vector_clock("node2".to_string(), 3, clock2);

        let merged = token1.merge(&token2);

        // Merged should have max of both clocks
        assert_eq!(merged.vector_clock.get("node1"), Some(&2));
        assert_eq!(merged.vector_clock.get("node2"), Some(&3));
        assert!(merged.is_after(&token1));
        assert!(merged.is_after(&token2));
    }

    #[test]
    fn test_encode_decode() {
        let token = RevisionToken::new("node1".to_string(), 42);

        let encoded = token.encode().unwrap();
        let decoded = RevisionToken::decode(&encoded).unwrap();

        assert_eq!(token, decoded);
    }

    #[test]
    fn test_validate_valid_token() {
        let token = RevisionToken::new("node1".to_string(), 5);
        assert!(token.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_node_id() {
        let token = RevisionToken::new("".to_string(), 5);
        assert!(token.validate().is_err());
    }

    #[test]
    fn test_validate_zero_revision() {
        let token = RevisionToken::new("node1".to_string(), 0);
        assert!(token.validate().is_err());
    }

    #[test]
    fn test_validate_missing_node_in_clock() {
        let mut clock = HashMap::new();
        clock.insert("node2".to_string(), 5);
        let token = RevisionToken::with_vector_clock("node1".to_string(), 5, clock);
        assert!(token.validate().is_err());
    }

    #[test]
    fn test_validate_mismatched_revision() {
        let mut clock = HashMap::new();
        clock.insert("node1".to_string(), 3);
        let token = RevisionToken::with_vector_clock("node1".to_string(), 5, clock);
        assert!(token.validate().is_err());
    }
}
