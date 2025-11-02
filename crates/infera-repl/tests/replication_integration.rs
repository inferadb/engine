//! Integration tests for multi-region replication
//!
//! These tests verify the complete replication system including:
//! - Cross-region replication
//! - Conflict resolution
//! - Network partition handling
//! - Failover scenarios

use infera_repl::{
    Change, ChangeFeed, Conflict, ConflictResolutionStrategy, ConflictResolver, NodeId, Operation,
    RegionId, ReplicationAgent, ReplicationConfig, ReplicationStrategy, Topology, TopologyBuilder,
    ZoneId,
};
use infera_store::{MemoryBackend, RelationshipStore};
use infera_types::{Relationship, Revision};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Helper to create a test relationship
fn test_relationship(resource: &str, relation: &str, subject: &str) -> Relationship {
    Relationship {
        vault: uuid::Uuid::nil(),
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: subject.to_string(),
    }
}

/// Helper to create a test change
fn test_change(relationship: Relationship, operation: Operation, timestamp: u64) -> Change {
    Change {
        revision: Revision(1),
        operation,
        relationship,
        timestamp,
        metadata: None,
    }
}

#[tokio::test]
async fn test_conflict_resolution_last_write_wins() {
    let resolver = ConflictResolver::new(ConflictResolutionStrategy::LastWriteWins);

    // Simulate concurrent writes from two regions
    let relationship = test_relationship("doc:readme", "viewer", "user:alice");

    let local = test_change(relationship.clone(), Operation::Insert, 1000);
    let remote = test_change(relationship, Operation::Delete, 2000);

    let conflict = Conflict::new(local, remote);
    let resolution = resolver.resolve(&conflict).unwrap();

    // Remote has later timestamp, should win
    assert!(matches!(resolution, infera_repl::Resolution::KeepRemote));
}

#[tokio::test]
async fn test_conflict_resolution_source_priority() {
    let resolver = ConflictResolver::new(ConflictResolutionStrategy::SourcePriority)
        .with_region_priorities(vec![
            "us-west".to_string(),
            "eu-central".to_string(),
            "ap-southeast".to_string(),
        ]);

    let relationship = test_relationship("doc:readme", "viewer", "user:alice");

    // Both changes at same time, different sources
    let mut local = test_change(relationship.clone(), Operation::Insert, 1000);
    local.metadata = Some(infera_repl::ChangeMetadata {
        source_node: Some("us-west".to_string()),
        causality_token: None,
        tags: std::collections::HashMap::new(),
    });

    let mut remote = test_change(relationship, Operation::Delete, 1000);
    remote.metadata = Some(infera_repl::ChangeMetadata {
        source_node: Some("ap-southeast".to_string()),
        causality_token: None,
        tags: std::collections::HashMap::new(),
    });

    let conflict = Conflict::new(local, remote);
    let resolution = resolver.resolve(&conflict).unwrap();

    // ap-southeast has higher priority (index 2 vs 0), should win
    assert!(matches!(resolution, infera_repl::Resolution::KeepRemote));
}

#[tokio::test]
async fn test_conflict_resolution_insert_wins() {
    let resolver = ConflictResolver::new(ConflictResolutionStrategy::InsertWins);

    let relationship = test_relationship("doc:readme", "viewer", "user:alice");

    // Insert vs Delete
    let local = test_change(relationship.clone(), Operation::Insert, 1000);
    let remote = test_change(relationship, Operation::Delete, 2000);

    let conflict = Conflict::new(local, remote);
    let resolution = resolver.resolve(&conflict).unwrap();

    // Insert wins even though delete has later timestamp
    assert!(matches!(resolution, infera_repl::Resolution::KeepLocal));
}

#[tokio::test]
async fn test_multiple_conflicts_in_sequence() {
    let resolver = ConflictResolver::new(ConflictResolutionStrategy::LastWriteWins);

    // Simulate a sequence of conflicting writes
    let relationship = test_relationship("doc:readme", "viewer", "user:alice");

    let changes = vec![
        test_change(relationship.clone(), Operation::Insert, 1000),
        test_change(relationship.clone(), Operation::Delete, 2000),
        test_change(relationship.clone(), Operation::Insert, 3000),
        test_change(relationship.clone(), Operation::Delete, 4000),
    ];

    // Process conflicts sequentially
    let mut current = changes[0].clone();
    for next in &changes[1..] {
        if resolver.detect_conflict(&current, next) {
            let conflict = Conflict::new(current.clone(), next.clone());
            let resolution = resolver.resolve(&conflict).unwrap();
            current = match resolution {
                infera_repl::Resolution::KeepLocal => current,
                infera_repl::Resolution::KeepRemote => next.clone(),
                _ => panic!("Unexpected resolution"),
            };
        }
    }

    // Final state should be the delete at timestamp 4000
    assert_eq!(current.operation, Operation::Delete);
    assert_eq!(current.timestamp, 4000);
}

#[tokio::test]
async fn test_topology_active_active() {
    let topology = TopologyBuilder::new(
        ReplicationStrategy::ActiveActive,
        RegionId::new("us-west-1"),
    )
    .add_region(RegionId::new("us-west-1"), "US West 1".to_string(), false)
    .add_zone(
        RegionId::new("us-west-1"),
        ZoneId::new("us-west-1a"),
        "Zone A".to_string(),
    )
    .add_node(
        RegionId::new("us-west-1"),
        ZoneId::new("us-west-1a"),
        NodeId::new("node1"),
        "localhost:50051".to_string(),
    )
    .add_region(
        RegionId::new("eu-central-1"),
        "EU Central 1".to_string(),
        false,
    )
    .add_zone(
        RegionId::new("eu-central-1"),
        ZoneId::new("eu-central-1a"),
        "Zone A".to_string(),
    )
    .add_node(
        RegionId::new("eu-central-1"),
        ZoneId::new("eu-central-1a"),
        NodeId::new("node2"),
        "localhost:50052".to_string(),
    )
    .set_replication_targets(
        RegionId::new("us-west-1"),
        vec![RegionId::new("eu-central-1")],
    )
    .set_replication_targets(
        RegionId::new("eu-central-1"),
        vec![RegionId::new("us-west-1")],
    )
    .build()
    .unwrap();

    // Verify topology
    assert_eq!(topology.regions.len(), 2);
    assert_eq!(topology.strategy, ReplicationStrategy::ActiveActive);

    // Verify replication graph
    let us_targets = topology.get_replication_targets(&RegionId::new("us-west-1"));
    assert_eq!(us_targets.len(), 1);
    assert_eq!(*us_targets[0], RegionId::new("eu-central-1"));

    let eu_targets = topology.get_replication_targets(&RegionId::new("eu-central-1"));
    assert_eq!(eu_targets.len(), 1);
    assert_eq!(*eu_targets[0], RegionId::new("us-west-1"));
}

#[tokio::test]
async fn test_topology_primary_replica() {
    let topology = TopologyBuilder::new(
        ReplicationStrategy::PrimaryReplica,
        RegionId::new("us-west-1"),
    )
    .add_region(
        RegionId::new("us-west-1"),
        "US West 1".to_string(),
        true, // primary
    )
    .add_region(
        RegionId::new("eu-central-1"),
        "EU Central 1".to_string(),
        false, // replica
    )
    .add_region(
        RegionId::new("ap-southeast-1"),
        "AP Southeast 1".to_string(),
        false, // replica
    )
    .set_replication_targets(
        RegionId::new("us-west-1"),
        vec![
            RegionId::new("eu-central-1"),
            RegionId::new("ap-southeast-1"),
        ],
    )
    .build()
    .unwrap();

    // Verify primary region
    let primary = topology.get_primary_region().unwrap();
    assert_eq!(primary.id, RegionId::new("us-west-1"));

    // Verify replication targets
    let targets = topology.get_replication_targets(&RegionId::new("us-west-1"));
    assert_eq!(targets.len(), 2);
}

#[tokio::test]
async fn test_topology_validation_no_primary() {
    let mut topology = Topology::new(
        ReplicationStrategy::PrimaryReplica,
        RegionId::new("us-west-1"),
    );
    topology.add_region(infera_repl::Region::new(
        RegionId::new("us-west-1"),
        "US West 1".to_string(),
        false, // not primary!
    ));

    let result = topology.validate();
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        infera_repl::TopologyError::NoPrimaryRegion
    ));
}

#[tokio::test]
async fn test_topology_validation_multiple_primary() {
    let mut topology = Topology::new(
        ReplicationStrategy::PrimaryReplica,
        RegionId::new("us-west-1"),
    );
    topology.add_region(infera_repl::Region::new(
        RegionId::new("us-west-1"),
        "US West 1".to_string(),
        true, // primary
    ));
    topology.add_region(infera_repl::Region::new(
        RegionId::new("eu-central-1"),
        "EU Central 1".to_string(),
        true, // also primary!
    ));

    let result = topology.validate();
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        infera_repl::TopologyError::MultiplePrimaryRegions
    ));
}

#[tokio::test]
async fn test_change_feed_integration() {
    let change_feed = Arc::new(ChangeFeed::new());

    // Subscribe to changes
    let mut stream1 = change_feed.subscribe().await.unwrap();
    let mut stream2 = change_feed.subscribe().await.unwrap();

    // Publish a change
    let relationship = test_relationship("doc:readme", "viewer", "user:alice");
    let change = test_change(relationship, Operation::Insert, 1000);

    change_feed.publish(change.clone()).await.unwrap();

    // Both subscribers should receive it
    let received1 = stream1.recv().await;
    let received2 = stream2.recv().await;

    assert!(received1.is_some());
    assert!(received2.is_some());

    assert_eq!(received1.unwrap().relationship.resource, "doc:readme");
    assert_eq!(received2.unwrap().relationship.resource, "doc:readme");
}

#[tokio::test]
async fn test_change_feed_with_filtering() {
    let change_feed = Arc::new(ChangeFeed::new());

    // Subscribe with resource type filter
    let mut stream = change_feed
        .subscribe_filtered("document".to_string())
        .await
        .unwrap();

    // Publish changes with different resource types
    let doc_relationship = test_relationship("document:readme", "viewer", "user:alice");
    let folder_relationship = test_relationship("folder:root", "viewer", "user:alice");

    change_feed
        .publish(test_change(doc_relationship, Operation::Insert, 1000))
        .await
        .unwrap();
    change_feed
        .publish(test_change(folder_relationship, Operation::Insert, 2000))
        .await
        .unwrap();

    // Should only receive the document change
    let received = stream.recv().await;
    assert!(received.is_some());
    assert_eq!(received.unwrap().relationship.resource, "document:readme");

    // Next receive should be None or folder (filtered out)
    // Due to filtering, the folder change should not appear
}

#[tokio::test]
async fn test_replication_agent_creation_and_shutdown() {
    let topology = Arc::new(RwLock::new(
        TopologyBuilder::new(
            ReplicationStrategy::ActiveActive,
            RegionId::new("us-west-1"),
        )
        .add_region(RegionId::new("us-west-1"), "US West".to_string(), false)
        .add_zone(
            RegionId::new("us-west-1"),
            ZoneId::new("us-west-1a"),
            "Zone A".to_string(),
        )
        .build()
        .unwrap(),
    ));

    let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());
    let change_feed = Arc::new(ChangeFeed::new());
    let conflict_resolver = Arc::new(ConflictResolver::new(
        ConflictResolutionStrategy::LastWriteWins,
    ));

    let mut agent = ReplicationAgent::new(
        topology,
        change_feed,
        store,
        conflict_resolver,
        ReplicationConfig::default(),
    );

    // Start agent
    agent.start().await.unwrap();

    // Give it a moment to initialize
    sleep(Duration::from_millis(10)).await;

    // Stop agent
    agent.stop().await;

    // Agent should shut down gracefully
}

#[tokio::test]
async fn test_network_partition_simulation() {
    // Simulate a network partition by creating a topology where a node becomes unreachable

    let mut topology = TopologyBuilder::new(
        ReplicationStrategy::ActiveActive,
        RegionId::new("us-west-1"),
    )
    .add_region(RegionId::new("us-west-1"), "US West 1".to_string(), false)
    .add_zone(
        RegionId::new("us-west-1"),
        ZoneId::new("us-west-1a"),
        "Zone A".to_string(),
    )
    .add_node(
        RegionId::new("us-west-1"),
        ZoneId::new("us-west-1a"),
        NodeId::new("node1"),
        "localhost:50051".to_string(),
    )
    .add_region(
        RegionId::new("eu-central-1"),
        "EU Central 1".to_string(),
        false,
    )
    .add_zone(
        RegionId::new("eu-central-1"),
        ZoneId::new("eu-central-1a"),
        "Zone A".to_string(),
    )
    .add_node(
        RegionId::new("eu-central-1"),
        ZoneId::new("eu-central-1a"),
        NodeId::new("node2"),
        "localhost:50052".to_string(),
    )
    .build()
    .unwrap();

    // Initially, all nodes are healthy
    let healthy = topology.get_healthy_nodes(&RegionId::new("eu-central-1"));
    assert_eq!(healthy.len(), 1);

    // Simulate partition by marking node as unreachable
    if let Some(region) = topology.get_region_mut(&RegionId::new("eu-central-1")) {
        if let Some(zone) = region.zones.get_mut(0) {
            if let Some(node) = zone.nodes.get_mut(0) {
                node.status = infera_repl::NodeStatus::Unreachable;
            }
        }
    }

    // Now no healthy nodes in that region
    let healthy = topology.get_healthy_nodes(&RegionId::new("eu-central-1"));
    assert_eq!(healthy.len(), 0);
}

#[tokio::test]
async fn test_concurrent_conflict_resolution() {
    let resolver = Arc::new(ConflictResolver::new(
        ConflictResolutionStrategy::LastWriteWins,
    ));

    // Simulate multiple concurrent conflicts
    let mut handles = vec![];

    for i in 0..100 {
        let resolver = Arc::clone(&resolver);
        let handle = tokio::spawn(async move {
            let relationship = test_relationship("doc:readme", "viewer", &format!("user:{}", i));
            let local = test_change(relationship.clone(), Operation::Insert, 1000 + i);
            let remote = test_change(relationship, Operation::Delete, 2000 + i);

            let conflict = Conflict::new(local, remote);
            resolver.resolve(&conflict).unwrap()
        });
        handles.push(handle);
    }

    // All resolutions should complete successfully
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(matches!(
            result,
            infera_repl::Resolution::KeepLocal | infera_repl::Resolution::KeepRemote
        ));
    }
}

#[tokio::test]
async fn test_failover_scenario() {
    // Test failover when primary region fails in PrimaryReplica strategy

    let topology = TopologyBuilder::new(
        ReplicationStrategy::PrimaryReplica,
        RegionId::new("us-west-1"),
    )
    .add_region(
        RegionId::new("us-west-1"),
        "US West 1".to_string(),
        true, // primary
    )
    .add_zone(
        RegionId::new("us-west-1"),
        ZoneId::new("us-west-1a"),
        "Zone A".to_string(),
    )
    .add_node(
        RegionId::new("us-west-1"),
        ZoneId::new("us-west-1a"),
        NodeId::new("node1"),
        "localhost:50051".to_string(),
    )
    .add_region(
        RegionId::new("eu-central-1"),
        "EU Central 1".to_string(),
        false, // replica
    )
    .add_zone(
        RegionId::new("eu-central-1"),
        ZoneId::new("eu-central-1a"),
        "Zone A".to_string(),
    )
    .add_node(
        RegionId::new("eu-central-1"),
        ZoneId::new("eu-central-1a"),
        NodeId::new("node2"),
        "localhost:50052".to_string(),
    )
    .build()
    .unwrap();

    // Primary region should be us-west-1
    let primary = topology.get_primary_region().unwrap();
    assert_eq!(primary.id, RegionId::new("us-west-1"));

    // In a real failover scenario:
    // 1. Detect primary is down (health checks)
    // 2. Promote replica to primary (update topology)
    // 3. Update replication graph
    // 4. Resume operations

    // For this test, we verify the topology structure supports this pattern
    assert!(topology
        .get_region(&RegionId::new("eu-central-1"))
        .is_some());
}

#[tokio::test]
async fn test_multi_region_write_propagation() {
    // Test that writes in one region can be replicated to others via change feed

    let change_feed = Arc::new(ChangeFeed::new());

    // Simulate "us-west" subscriber
    let mut us_stream = change_feed.subscribe().await.unwrap();

    // Simulate "eu-central" subscriber
    let mut eu_stream = change_feed.subscribe().await.unwrap();

    // Write from us-west region
    let relationship = test_relationship("doc:readme", "viewer", "user:alice");
    let mut change = test_change(relationship, Operation::Insert, 1000);
    change.metadata = Some(infera_repl::ChangeMetadata {
        source_node: Some("us-west-node1".to_string()),
        causality_token: None,
        tags: std::collections::HashMap::new(),
    });

    change_feed.publish(change.clone()).await.unwrap();

    // Both regions should receive the change
    let us_received = us_stream.recv().await.unwrap();
    let eu_received = eu_stream.recv().await.unwrap();

    assert_eq!(us_received.relationship.resource, "doc:readme");
    assert_eq!(eu_received.relationship.resource, "doc:readme");

    assert_eq!(
        us_received.metadata.as_ref().unwrap().source_node,
        Some("us-west-node1".to_string())
    );
}

#[tokio::test]
async fn test_cross_region_conflict_with_metadata() {
    // Test conflict resolution with source metadata

    let resolver = ConflictResolver::new(ConflictResolutionStrategy::SourcePriority)
        .with_region_priorities(vec!["us-west".to_string(), "eu-central".to_string()]);

    let relationship = test_relationship("doc:readme", "viewer", "user:alice");

    let mut us_change = test_change(relationship.clone(), Operation::Insert, 1000);
    us_change.metadata = Some(infera_repl::ChangeMetadata {
        source_node: Some("us-west".to_string()),
        causality_token: None,
        tags: std::collections::HashMap::new(),
    });

    let mut eu_change = test_change(relationship, Operation::Delete, 1000);
    eu_change.metadata = Some(infera_repl::ChangeMetadata {
        source_node: Some("eu-central".to_string()),
        causality_token: None,
        tags: std::collections::HashMap::new(),
    });

    let conflict = Conflict::new(us_change, eu_change);
    let resolution = resolver.resolve(&conflict).unwrap();

    // eu-central has higher priority (index 1 vs 0), should win
    assert!(matches!(resolution, infera_repl::Resolution::KeepRemote));
}

#[tokio::test]
async fn test_replication_config_customization() {
    let config = ReplicationConfig {
        max_retries: 10,
        retry_delay: Duration::from_millis(200),
        batch_size: 50,
        request_timeout: Duration::from_secs(5),
        buffer_size: 5000,
    };

    assert_eq!(config.max_retries, 10);
    assert_eq!(config.batch_size, 50);
    assert_eq!(config.buffer_size, 5000);
}
