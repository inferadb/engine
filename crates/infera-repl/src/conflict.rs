//! # Conflict Resolution
//!
//! Implements conflict detection and resolution strategies for multi-region replication.
//! When the same relationship is modified concurrently in different regions, conflicts must be
//! detected and resolved deterministically across all replicas.

use std::cmp::Ordering;

use infera_types::Relationship;
use serde::{Deserialize, Serialize};

use crate::{Change, Operation, ReplError};

/// Represents a conflict between two concurrent changes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The local change
    pub local: Change,
    /// The remote change that conflicts
    pub remote: Change,
    /// The relationship affected
    pub relationship: Relationship,
}

impl Conflict {
    pub fn new(local: Change, remote: Change) -> Self {
        Self { relationship: local.relationship.clone(), local, remote }
    }
}

/// Strategy for resolving conflicts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolutionStrategy {
    /// Last Write Wins - use timestamp to determine winner
    /// Simplest strategy, works well when clocks are synchronized
    LastWriteWins,

    /// Source region priority - conflicts resolved based on region priority
    /// Useful when you want certain regions to take precedence
    SourcePriority,

    /// Insert wins - if one operation is insert and other is delete, insert wins
    /// Helps prevent data loss in certain scenarios
    InsertWins,

    /// Custom - application-defined resolution logic
    /// Most flexible, requires custom implementation
    Custom,
}

/// Result of conflict resolution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Keep the local change, discard remote
    KeepLocal,
    /// Keep the remote change, discard local
    KeepRemote,
    /// Both changes should be kept (rare, application-specific)
    KeepBoth,
    /// Custom resolution with a new merged change
    Merge(Box<Change>),
}

/// Conflict resolver that applies a resolution strategy
pub struct ConflictResolver {
    strategy: ConflictResolutionStrategy,
    /// Priority ordering of source regions (for SourcePriority strategy)
    /// Higher index = higher priority
    region_priorities: Vec<String>,
}

impl ConflictResolver {
    /// Create a new resolver with the given strategy
    pub fn new(strategy: ConflictResolutionStrategy) -> Self {
        Self { strategy, region_priorities: Vec::new() }
    }

    /// Set region priorities for SourcePriority strategy
    /// Regions later in the list have higher priority
    pub fn with_region_priorities(mut self, priorities: Vec<String>) -> Self {
        self.region_priorities = priorities;
        self
    }

    /// Detect if two changes conflict
    pub fn detect_conflict(&self, local: &Change, remote: &Change) -> bool {
        // Changes conflict if they affect the same relationship
        if local.relationship != remote.relationship {
            return false;
        }

        // If both are the same operation with same timestamp, not a conflict
        if local.operation == remote.operation && local.timestamp == remote.timestamp {
            return false;
        }

        // Different operations or timestamps on same relationship = conflict
        true
    }

    /// Resolve a conflict between local and remote changes
    pub fn resolve(&self, conflict: &Conflict) -> Result<Resolution, ReplError> {
        match self.strategy {
            ConflictResolutionStrategy::LastWriteWins => self.resolve_lww(conflict),
            ConflictResolutionStrategy::SourcePriority => self.resolve_source_priority(conflict),
            ConflictResolutionStrategy::InsertWins => self.resolve_insert_wins(conflict),
            ConflictResolutionStrategy::Custom => {
                // Custom resolution must be implemented by caller
                Err(ReplError::Conflict)
            },
        }
    }

    /// Last Write Wins resolution
    fn resolve_lww(&self, conflict: &Conflict) -> Result<Resolution, ReplError> {
        match conflict.local.timestamp.cmp(&conflict.remote.timestamp) {
            Ordering::Greater => Ok(Resolution::KeepLocal),
            Ordering::Less => Ok(Resolution::KeepRemote),
            Ordering::Equal => {
                // Timestamps equal, use source node as tiebreaker
                self.resolve_by_source_node(conflict)
            },
        }
    }

    /// Source priority resolution
    fn resolve_source_priority(&self, conflict: &Conflict) -> Result<Resolution, ReplError> {
        let local_source =
            conflict.local.metadata.as_ref().and_then(|m| m.source_node.as_deref()).unwrap_or("");

        let remote_source =
            conflict.remote.metadata.as_ref().and_then(|m| m.source_node.as_deref()).unwrap_or("");

        let local_priority = self.get_region_priority(local_source);
        let remote_priority = self.get_region_priority(remote_source);

        match local_priority.cmp(&remote_priority) {
            Ordering::Greater => Ok(Resolution::KeepLocal),
            Ordering::Less => Ok(Resolution::KeepRemote),
            Ordering::Equal => {
                // Same priority, fall back to LWW
                self.resolve_lww(conflict)
            },
        }
    }

    /// Insert wins resolution
    fn resolve_insert_wins(&self, conflict: &Conflict) -> Result<Resolution, ReplError> {
        match (conflict.local.operation, conflict.remote.operation) {
            (Operation::Insert, Operation::Delete) => Ok(Resolution::KeepLocal),
            (Operation::Delete, Operation::Insert) => Ok(Resolution::KeepRemote),
            _ => {
                // Both same operation, fall back to LWW
                self.resolve_lww(conflict)
            },
        }
    }

    /// Resolve conflict by source node (lexicographic comparison)
    fn resolve_by_source_node(&self, conflict: &Conflict) -> Result<Resolution, ReplError> {
        let local_source =
            conflict.local.metadata.as_ref().and_then(|m| m.source_node.as_deref()).unwrap_or("");

        let remote_source =
            conflict.remote.metadata.as_ref().and_then(|m| m.source_node.as_deref()).unwrap_or("");

        match local_source.cmp(remote_source) {
            Ordering::Greater => Ok(Resolution::KeepLocal),
            Ordering::Less => Ok(Resolution::KeepRemote),
            Ordering::Equal => {
                // Shouldn't happen (same source, same timestamp), but keep local as fallback
                Ok(Resolution::KeepLocal)
            },
        }
    }

    /// Get priority for a region (higher = more priority)
    fn get_region_priority(&self, region: &str) -> usize {
        self.region_priorities.iter().position(|r| r == region).unwrap_or(0)
    }
}

/// Statistics about conflict resolution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConflictStats {
    /// Total number of conflicts detected
    pub conflicts_detected: u64,
    /// Conflicts resolved by keeping local
    pub kept_local: u64,
    /// Conflicts resolved by keeping remote
    pub kept_remote: u64,
    /// Conflicts resolved by merging
    pub merged: u64,
    /// Conflicts that failed to resolve
    pub failed: u64,
}

impl ConflictStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_conflict(&mut self, resolution: &Resolution) {
        self.conflicts_detected += 1;
        match resolution {
            Resolution::KeepLocal => self.kept_local += 1,
            Resolution::KeepRemote => self.kept_remote += 1,
            Resolution::KeepBoth | Resolution::Merge(_) => self.merged += 1,
        }
    }

    pub fn record_failure(&mut self) {
        self.conflicts_detected += 1;
        self.failed += 1;
    }

    /// Get conflict rate (conflicts per total operations)
    pub fn conflict_rate(&self, total_operations: u64) -> f64 {
        if total_operations == 0 {
            return 0.0;
        }
        self.conflicts_detected as f64 / total_operations as f64
    }
}

#[cfg(test)]
mod tests {
    use infera_types::Revision;

    use super::*;
    use crate::ChangeMetadata;
    fn create_test_relationship() -> Relationship {
        Relationship {
            vault: 0,
            resource: "doc:test".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        }
    }

    fn create_change_with_metadata(
        timestamp: u64,
        operation: Operation,
        source_node: &str,
    ) -> Change {
        let metadata = ChangeMetadata {
            source_node: Some(source_node.to_string()),
            causality_token: None,
            tags: std::collections::HashMap::new(),
        };

        Change {
            revision: Revision(1),
            operation,
            relationship: create_test_relationship(),
            timestamp,
            metadata: Some(metadata),
        }
    }

    #[test]
    fn test_conflict_detection() {
        let resolver = ConflictResolver::new(ConflictResolutionStrategy::LastWriteWins);

        let change1 = create_change_with_metadata(1000, Operation::Insert, "node1");
        let change2 = create_change_with_metadata(2000, Operation::Delete, "node2");

        // Same relationship, different operations = conflict
        assert!(resolver.detect_conflict(&change1, &change2));

        // Same relationship, same operation, different timestamp = conflict
        let change3 = create_change_with_metadata(1000, Operation::Insert, "node1");
        let change4 = create_change_with_metadata(2000, Operation::Insert, "node2");
        assert!(resolver.detect_conflict(&change3, &change4));

        // Different relationships = no conflict
        let mut change5 = change1.clone();
        change5.relationship.subject = "user:bob".to_string();
        assert!(!resolver.detect_conflict(&change1, &change5));
    }

    #[test]
    fn test_lww_resolution() {
        let resolver = ConflictResolver::new(ConflictResolutionStrategy::LastWriteWins);

        let local = create_change_with_metadata(1000, Operation::Insert, "node1");
        let remote = create_change_with_metadata(2000, Operation::Insert, "node2");

        let conflict = Conflict::new(local.clone(), remote.clone());
        let resolution = resolver.resolve(&conflict).unwrap();

        // Remote has later timestamp, should win
        assert_eq!(resolution, Resolution::KeepRemote);

        // Reverse timestamps
        let conflict2 = Conflict::new(remote, local);
        let resolution2 = resolver.resolve(&conflict2).unwrap();
        assert_eq!(resolution2, Resolution::KeepLocal);
    }

    #[test]
    fn test_lww_tiebreaker() {
        let resolver = ConflictResolver::new(ConflictResolutionStrategy::LastWriteWins);

        // Same timestamp, different source nodes
        let local = create_change_with_metadata(1000, Operation::Insert, "node-b");
        let remote = create_change_with_metadata(1000, Operation::Insert, "node-a");

        let conflict = Conflict::new(local, remote);
        let resolution = resolver.resolve(&conflict).unwrap();

        // Should use lexicographic comparison of source nodes
        // "node-b" > "node-a", so keep local
        assert_eq!(resolution, Resolution::KeepLocal);
    }

    #[test]
    fn test_source_priority_resolution() {
        let resolver = ConflictResolver::new(ConflictResolutionStrategy::SourcePriority)
            .with_region_priorities(vec![
                "us-west".to_string(),
                "eu-central".to_string(),
                "ap-southeast".to_string(),
            ]);

        let local = create_change_with_metadata(1000, Operation::Insert, "us-west");
        let remote = create_change_with_metadata(2000, Operation::Insert, "ap-southeast");

        let conflict = Conflict::new(local, remote);
        let resolution = resolver.resolve(&conflict).unwrap();

        // ap-southeast has higher priority (index 2 vs 0), should win
        assert_eq!(resolution, Resolution::KeepRemote);
    }

    #[test]
    fn test_insert_wins_resolution() {
        let resolver = ConflictResolver::new(ConflictResolutionStrategy::InsertWins);

        // Insert vs Delete
        let local = create_change_with_metadata(1000, Operation::Insert, "node1");
        let remote = create_change_with_metadata(2000, Operation::Delete, "node2");

        let conflict = Conflict::new(local, remote);
        let resolution = resolver.resolve(&conflict).unwrap();

        // Insert wins even though delete has later timestamp
        assert_eq!(resolution, Resolution::KeepLocal);

        // Delete vs Insert
        let local2 = create_change_with_metadata(2000, Operation::Delete, "node1");
        let remote2 = create_change_with_metadata(1000, Operation::Insert, "node2");

        let conflict2 = Conflict::new(local2, remote2);
        let resolution2 = resolver.resolve(&conflict2).unwrap();

        // Insert wins
        assert_eq!(resolution2, Resolution::KeepRemote);
    }

    #[test]
    fn test_conflict_stats() {
        let mut stats = ConflictStats::new();

        stats.record_conflict(&Resolution::KeepLocal);
        stats.record_conflict(&Resolution::KeepRemote);
        stats.record_conflict(&Resolution::KeepLocal);
        stats.record_failure();

        assert_eq!(stats.conflicts_detected, 4);
        assert_eq!(stats.kept_local, 2);
        assert_eq!(stats.kept_remote, 1);
        assert_eq!(stats.failed, 1);

        // Conflict rate: 4 conflicts / 100 total operations = 4%
        assert_eq!(stats.conflict_rate(100), 0.04);
    }
}
