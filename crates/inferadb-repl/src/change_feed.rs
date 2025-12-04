//! # Change Feed
//!
//! Implements change streaming for replication and event-driven updates.
//! Supports multiple subscribers, filtering, and reconnection handling.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use inferadb_const::DEFAULT_CHANNEL_CAPACITY;
use inferadb_types::{Relationship, Revision};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};

use crate::{ReplError, Result};

/// A change event representing a relationship operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    /// The revision at which this change occurred
    pub revision: Revision,
    /// The type of operation (insert or delete)
    pub operation: Operation,
    /// The relationship affected by this operation
    pub relationship: Relationship,
    /// Timestamp when the change occurred (Unix timestamp in milliseconds)
    pub timestamp: u64,
    /// Optional metadata for the change
    pub metadata: Option<ChangeMetadata>,
}

impl Change {
    /// Create a new insert operation change event
    pub fn insert(revision: Revision, relationship: Relationship) -> Self {
        Self {
            revision,
            operation: Operation::Insert,
            relationship,
            timestamp: Self::current_timestamp(),
            metadata: None,
        }
    }

    /// Create a new delete operation change event
    pub fn delete(revision: Revision, relationship: Relationship) -> Self {
        Self {
            revision,
            operation: Operation::Delete,
            relationship,
            timestamp: Self::current_timestamp(),
            metadata: None,
        }
    }

    /// Add metadata to this change event
    pub fn with_metadata(mut self, metadata: ChangeMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Get the resource type from the relationship object
    pub fn resource_type(&self) -> Option<&str> {
        self.relationship.resource.split(':').next()
    }

    fn current_timestamp() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
    }
}

/// Type of operation performed on a relationship
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Operation {
    /// Relationship was inserted
    Insert,
    /// Relationship was deleted
    Delete,
}

/// Optional metadata for change events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeMetadata {
    /// Source node that generated this change
    pub source_node: Option<String>,
    /// Causality token for ordering
    pub causality_token: Option<String>,
    /// Custom metadata tags
    pub tags: std::collections::HashMap<String, String>,
}

/// Configuration for the change feed
#[derive(Debug, Clone)]
pub struct ChangeFeedConfig {
    /// Channel capacity for buffering events
    pub channel_capacity: usize,
}

impl Default for ChangeFeedConfig {
    fn default() -> Self {
        Self { channel_capacity: DEFAULT_CHANNEL_CAPACITY }
    }
}

/// Change feed publisher and subscription manager
pub struct ChangeFeed {
    /// Broadcast channel for publishing changes
    tx: broadcast::Sender<Change>,
    /// Configuration
    config: ChangeFeedConfig,
    /// Statistics
    stats: Arc<RwLock<ChangeFeedStats>>,
}

/// Statistics about the change feed
#[derive(Debug, Clone, Default)]
pub struct ChangeFeedStats {
    /// Total number of changes published
    pub published: u64,
    /// Total number of active subscribers
    pub subscribers: usize,
    /// Total number of dropped events (buffer full)
    pub dropped: u64,
}

impl ChangeFeed {
    /// Create a new change feed with default configuration
    pub fn new() -> Self {
        Self::with_config(ChangeFeedConfig::default())
    }

    /// Create a new change feed with custom configuration
    pub fn with_config(config: ChangeFeedConfig) -> Self {
        let (tx, _) = broadcast::channel(config.channel_capacity);
        Self { tx, config, stats: Arc::new(RwLock::new(ChangeFeedStats::default())) }
    }

    /// Publish a change event to all subscribers
    pub async fn publish(&self, change: Change) -> Result<()> {
        let mut stats = self.stats.write().await;

        // Attempt to send the change
        match self.tx.send(change) {
            Ok(count) => {
                stats.published += 1;
                stats.subscribers = count;
                Ok(())
            },
            Err(_) => {
                // No active subscribers, which is fine
                stats.published += 1;
                Ok(())
            },
        }
    }

    /// Subscribe to the change feed
    pub async fn subscribe(&self) -> Result<ChangeStream> {
        let rx = self.tx.subscribe();
        let mut stats = self.stats.write().await;
        stats.subscribers = self.tx.receiver_count();

        Ok(ChangeStream { rx, filter: None })
    }

    /// Subscribe to the change feed with a resource type filter
    pub async fn subscribe_filtered(&self, resource_type: String) -> Result<ChangeStream> {
        let rx = self.tx.subscribe();
        let mut stats = self.stats.write().await;
        stats.subscribers = self.tx.receiver_count();

        Ok(ChangeStream { rx, filter: Some(ChangeFilter::ResourceType(resource_type)) })
    }

    /// Get current statistics
    pub async fn stats(&self) -> ChangeFeedStats {
        self.stats.read().await.clone()
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Get the current configuration
    pub fn config(&self) -> &ChangeFeedConfig {
        &self.config
    }
}

impl Default for ChangeFeed {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter for change events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeFilter {
    /// Filter by resource type (e.g., "document", "folder")
    ResourceType(String),
    /// Filter by relation
    Relation(String),
    /// Filter by operation type
    Operation(Operation),
}

impl ChangeFilter {
    /// Check if a change matches this filter
    pub fn matches(&self, change: &Change) -> bool {
        match self {
            ChangeFilter::ResourceType(type_name) => {
                change.resource_type() == Some(type_name.as_str())
            },
            ChangeFilter::Relation(relation) => &change.relationship.relation == relation,
            ChangeFilter::Operation(op) => change.operation == *op,
        }
    }
}

/// Stream of change events
pub struct ChangeStream {
    rx: broadcast::Receiver<Change>,
    filter: Option<ChangeFilter>,
}

impl ChangeStream {
    /// Receive the next change event
    ///
    /// Returns None if the stream is closed or lagged (lost events).
    /// Clients should handle lagged streams by resyncing.
    pub async fn recv(&mut self) -> Option<Change> {
        loop {
            match self.rx.recv().await {
                Ok(change) => {
                    // Apply filter if present
                    if let Some(filter) = &self.filter {
                        if !filter.matches(&change) {
                            continue; // Skip filtered out changes
                        }
                    }
                    return Some(change);
                },
                Err(broadcast::error::RecvError::Closed) => {
                    return None;
                },
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // The receiver lagged behind and lost events
                    // Return None to signal the client should resync
                    return None;
                },
            }
        }
    }

    /// Try to receive a change without blocking
    pub fn try_recv(&mut self) -> Result<Option<Change>> {
        loop {
            match self.rx.try_recv() {
                Ok(change) => {
                    // Apply filter if present
                    if let Some(filter) = &self.filter {
                        if !filter.matches(&change) {
                            continue; // Skip filtered out changes
                        }
                    }
                    return Ok(Some(change));
                },
                Err(broadcast::error::TryRecvError::Empty) => {
                    return Ok(None);
                },
                Err(broadcast::error::TryRecvError::Closed) => {
                    return Err(ReplError::Replication("Stream closed".to_string()));
                },
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    return Err(ReplError::Replication(
                        "Stream lagged, resync required".to_string(),
                    ));
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_creation() {
        let relationship = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let change = Change::insert(Revision(1), relationship.clone());
        assert_eq!(change.revision, Revision(1));
        assert_eq!(change.operation, Operation::Insert);
        assert_eq!(change.relationship, relationship);
        assert!(change.timestamp > 0);
        assert!(change.metadata.is_none());
    }

    #[test]
    fn test_change_with_metadata() {
        let relationship = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let metadata = ChangeMetadata {
            source_node: Some("node1".to_string()),
            causality_token: Some("token123".to_string()),
            tags: std::collections::HashMap::new(),
        };

        let change = Change::insert(Revision(1), relationship).with_metadata(metadata.clone());
        assert_eq!(change.metadata, Some(metadata));
    }

    #[test]
    fn test_resource_type_extraction() {
        let relationship = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let change = Change::insert(Revision(1), relationship);
        assert_eq!(change.resource_type(), Some("doc"));
    }

    #[test]
    fn test_filter_resource_type() {
        let relationship1 = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        let relationship2 = Relationship {
            vault: 0,
            resource: "folder:shared".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let change1 = Change::insert(Revision(1), relationship1);
        let change2 = Change::insert(Revision(2), relationship2);

        let filter = ChangeFilter::ResourceType("doc".to_string());
        assert!(filter.matches(&change1));
        assert!(!filter.matches(&change2));
    }

    #[test]
    fn test_filter_relation() {
        let relationship1 = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        let relationship2 = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "editor".to_string(),
            subject: "user:alice".to_string(),
        };

        let change1 = Change::insert(Revision(1), relationship1);
        let change2 = Change::insert(Revision(2), relationship2);

        let filter = ChangeFilter::Relation("viewer".to_string());
        assert!(filter.matches(&change1));
        assert!(!filter.matches(&change2));
    }

    #[test]
    fn test_filter_operation() {
        let relationship = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let insert_change = Change::insert(Revision(1), relationship.clone());
        let delete_change = Change::delete(Revision(2), relationship);

        let filter = ChangeFilter::Operation(Operation::Insert);
        assert!(filter.matches(&insert_change));
        assert!(!filter.matches(&delete_change));
    }

    #[tokio::test]
    async fn test_publish_and_subscribe() {
        let feed = ChangeFeed::new();
        let mut stream = feed.subscribe().await.unwrap();

        let relationship = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let change = Change::insert(Revision(1), relationship.clone());
        feed.publish(change.clone()).await.unwrap();

        let received = stream.recv().await.unwrap();
        assert_eq!(received.revision, change.revision);
        assert_eq!(received.relationship, change.relationship);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let feed = ChangeFeed::new();
        let mut stream1 = feed.subscribe().await.unwrap();
        let mut stream2 = feed.subscribe().await.unwrap();

        let relationship = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let change = Change::insert(Revision(1), relationship);
        feed.publish(change.clone()).await.unwrap();

        let received1 = stream1.recv().await.unwrap();
        let received2 = stream2.recv().await.unwrap();

        assert_eq!(received1.revision, change.revision);
        assert_eq!(received2.revision, change.revision);
    }

    #[tokio::test]
    async fn test_filtered_subscription() {
        let feed = ChangeFeed::new();
        let mut stream = feed.subscribe_filtered("doc".to_string()).await.unwrap();

        let relationship1 = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };
        let relationship2 = Relationship {
            vault: 0,
            resource: "folder:shared".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
        };

        // Publish both changes
        feed.publish(Change::insert(Revision(1), relationship1.clone())).await.unwrap();
        feed.publish(Change::insert(Revision(2), relationship2)).await.unwrap();
        feed.publish(Change::insert(Revision(3), relationship1.clone())).await.unwrap();

        // Should only receive doc changes
        let received1 = stream.recv().await.unwrap();
        assert_eq!(received1.relationship.resource, "doc:readme");
        assert_eq!(received1.revision, Revision(1));

        let received2 = stream.recv().await.unwrap();
        assert_eq!(received2.relationship.resource, "doc:readme");
        assert_eq!(received2.revision, Revision(3));
    }

    #[tokio::test]
    async fn test_try_recv() {
        let feed = ChangeFeed::new();
        let mut stream = feed.subscribe().await.unwrap();

        // Should be empty initially
        let result = stream.try_recv().unwrap();
        assert!(result.is_none());

        let relationship = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        feed.publish(Change::insert(Revision(1), relationship)).await.unwrap();

        // Should receive the change
        let received = stream.try_recv().unwrap().unwrap();
        assert_eq!(received.revision, Revision(1));

        // Should be empty again
        let result = stream.try_recv().unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_stats() {
        let feed = ChangeFeed::new();
        let _stream1 = feed.subscribe().await.unwrap();
        let _stream2 = feed.subscribe().await.unwrap();

        let relationship = Relationship {
            vault: 0,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        feed.publish(Change::insert(Revision(1), relationship.clone())).await.unwrap();
        feed.publish(Change::insert(Revision(2), relationship)).await.unwrap();

        let stats = feed.stats().await;
        assert_eq!(stats.published, 2);
        assert_eq!(stats.subscribers, 2);
    }

    #[tokio::test]
    async fn test_subscriber_count() {
        let feed = ChangeFeed::new();
        assert_eq!(feed.subscriber_count(), 0);

        let _stream1 = feed.subscribe().await.unwrap();
        assert_eq!(feed.subscriber_count(), 1);

        let _stream2 = feed.subscribe().await.unwrap();
        assert_eq!(feed.subscriber_count(), 2);
    }

    #[tokio::test]
    async fn test_custom_config() {
        let config = ChangeFeedConfig { channel_capacity: 10 };
        let feed = ChangeFeed::with_config(config);
        assert_eq!(feed.config.channel_capacity, 10);
    }
}
