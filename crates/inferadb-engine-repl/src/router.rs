//! # Region-Aware Routing
//!
//! Routes requests to appropriate regions based on replication strategy:
//! - For reads: route to local region for lowest latency
//! - For writes: route to primary (PrimaryReplica) or local (ActiveActive)
//! - Handle region failures with automatic failover
//! - Round-robin load balancing across healthy nodes

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::{
    ReplError, Result,
    topology::{NodeId, RegionId, ReplicationStrategy, Topology},
};

/// Request type for routing decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    /// Read request (check, expand)
    Read,
    /// Write request (write, delete)
    Write,
}

/// Routing decision
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDecision {
    /// Target region for this request
    pub region_id: RegionId,
    /// Target node within the region
    pub node_id: NodeId,
    /// Endpoint to connect to
    pub endpoint: String,
}

/// Load balancing strategy for selecting nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalancingStrategy {
    /// Round-robin across healthy nodes (default)
    #[default]
    RoundRobin,
    /// Always select the first healthy node
    FirstAvailable,
}

/// Region-aware request router with load balancing
pub struct Router {
    /// Topology configuration
    topology: Arc<RwLock<Topology>>,
    /// Load balancing strategy
    strategy: LoadBalancingStrategy,
    /// Round-robin counters per region (thread-safe)
    round_robin_counters: Arc<RwLock<HashMap<RegionId, AtomicUsize>>>,
}

impl Router {
    /// Create a new router with the given topology (defaults to round-robin)
    pub fn new(topology: Arc<RwLock<Topology>>) -> Self {
        Self {
            topology,
            strategy: LoadBalancingStrategy::RoundRobin,
            round_robin_counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new router with a specific load balancing strategy
    pub fn with_strategy(topology: Arc<RwLock<Topology>>, strategy: LoadBalancingStrategy) -> Self {
        Self { topology, strategy, round_robin_counters: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Route a request to the appropriate region and node
    pub async fn route(&self, request_type: RequestType) -> Result<RoutingDecision> {
        let topology = self.topology.read().await;

        match request_type {
            RequestType::Read => self.route_read(&topology).await,
            RequestType::Write => self.route_write(&topology).await,
        }
    }

    /// Select a node from a list using the configured load balancing strategy
    async fn select_node<'a>(
        &self,
        region_id: &RegionId,
        nodes: &'a [&'a crate::topology::Node],
    ) -> &'a crate::topology::Node {
        match self.strategy {
            LoadBalancingStrategy::FirstAvailable => nodes[0],
            LoadBalancingStrategy::RoundRobin => {
                let index = self.get_and_increment_counter(region_id).await;
                nodes[index % nodes.len()]
            },
        }
    }

    /// Get and increment the round-robin counter for a region
    async fn get_and_increment_counter(&self, region_id: &RegionId) -> usize {
        let mut counters = self.round_robin_counters.write().await;

        let counter = counters
            .entry(region_id.clone())
            .or_insert_with(|| AtomicUsize::new(0));

        counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Route a read request to the local region
    async fn route_read(&self, topology: &Topology) -> Result<RoutingDecision> {
        let local_region = &topology.local_region;

        // Get healthy nodes in local region
        let nodes = topology.get_healthy_nodes(local_region);

        if nodes.is_empty() {
            // No healthy nodes in local region, try to find a fallback
            warn!("No healthy nodes in local region {}, attempting failover", local_region);
            return self.find_fallback_region(topology, RequestType::Read).await;
        }

        // Select node using load balancing strategy
        let node = self.select_node(local_region, &nodes).await;

        Ok(RoutingDecision {
            region_id: local_region.clone(),
            node_id: node.id.clone(),
            endpoint: node.endpoint.clone(),
        })
    }

    /// Route a write request based on replication strategy
    async fn route_write(&self, topology: &Topology) -> Result<RoutingDecision> {
        match topology.strategy {
            ReplicationStrategy::PrimaryReplica => {
                // Route writes to primary region
                self.route_to_primary(topology).await
            },
            ReplicationStrategy::ActiveActive => {
                // Route writes to local region (all regions can accept writes)
                self.route_to_local(topology, RequestType::Write).await
            },
            ReplicationStrategy::MultiMaster => {
                // For multi-master, route to local region
                // (in a real implementation, this would check tenant/namespace partitioning)
                self.route_to_local(topology, RequestType::Write).await
            },
        }
    }

    /// Route to the primary region
    async fn route_to_primary(&self, topology: &Topology) -> Result<RoutingDecision> {
        let primary = topology
            .get_primary_region()
            .ok_or_else(|| ReplError::Replication("No primary region configured".to_string()))?;

        let nodes = topology.get_healthy_nodes(&primary.id);

        if nodes.is_empty() {
            warn!("No healthy nodes in primary region {}", primary.id);
            return Err(ReplError::Replication("Primary region has no healthy nodes".to_string()));
        }

        // Select node using load balancing strategy
        let node = self.select_node(&primary.id, &nodes).await;

        debug!("Routing write to primary region {} node {}", primary.id, node.id);

        Ok(RoutingDecision {
            region_id: primary.id.clone(),
            node_id: node.id.clone(),
            endpoint: node.endpoint.clone(),
        })
    }

    /// Route to local region
    async fn route_to_local(
        &self,
        topology: &Topology,
        request_type: RequestType,
    ) -> Result<RoutingDecision> {
        let local_region = &topology.local_region;

        let nodes = topology.get_healthy_nodes(local_region);

        if nodes.is_empty() {
            warn!("No healthy nodes in local region {}, attempting failover", local_region);
            return self.find_fallback_region(topology, request_type).await;
        }

        // Select node using load balancing strategy
        let node = self.select_node(local_region, &nodes).await;

        debug!("Routing {:?} to local region {} node {}", request_type, local_region, node.id);

        Ok(RoutingDecision {
            region_id: local_region.clone(),
            node_id: node.id.clone(),
            endpoint: node.endpoint.clone(),
        })
    }

    /// Find a fallback region when local region is unavailable
    async fn find_fallback_region(
        &self,
        topology: &Topology,
        request_type: RequestType,
    ) -> Result<RoutingDecision> {
        // For reads, any region with healthy nodes works
        // For writes in PrimaryReplica, must use primary
        // For writes in ActiveActive/MultiMaster, any region works

        if request_type == RequestType::Write
            && topology.strategy == ReplicationStrategy::PrimaryReplica
        {
            return self.route_to_primary(topology).await;
        }

        // Find any region with healthy nodes
        for region in &topology.regions {
            if region.id == topology.local_region {
                continue; // Already checked local region
            }

            let nodes = topology.get_healthy_nodes(&region.id);
            if !nodes.is_empty() {
                // Select node using load balancing strategy
                let node = self.select_node(&region.id, &nodes).await;

                warn!(
                    "Failover: routing {:?} to fallback region {} node {}",
                    request_type, region.id, node.id
                );

                return Ok(RoutingDecision {
                    region_id: region.id.clone(),
                    node_id: node.id.clone(),
                    endpoint: node.endpoint.clone(),
                });
            }
        }

        Err(ReplError::Replication("No healthy nodes in any region".to_string()))
    }

    /// Check if a specific region is available
    pub async fn is_region_available(&self, region_id: &RegionId) -> bool {
        let topology = self.topology.read().await;
        !topology.get_healthy_nodes(region_id).is_empty()
    }

    /// Get all available regions
    pub async fn get_available_regions(&self) -> Vec<RegionId> {
        let topology = self.topology.read().await;
        topology
            .regions
            .iter()
            .filter(|r| !topology.get_healthy_nodes(&r.id).is_empty())
            .map(|r| r.id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{TopologyBuilder, ZoneId};

    async fn create_test_topology_active_active() -> Arc<RwLock<Topology>> {
        Arc::new(RwLock::new(
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
                .add_region(RegionId::new("us-west-1"), "US West".to_string(), false)
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
                .add_region(RegionId::new("eu-central-1"), "EU Central".to_string(), false)
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
                .unwrap(),
        ))
    }

    async fn create_test_topology_primary_replica() -> Arc<RwLock<Topology>> {
        Arc::new(RwLock::new(
            TopologyBuilder::new(ReplicationStrategy::PrimaryReplica, RegionId::new("us-west-1"))
                .add_region(
                    RegionId::new("us-west-1"),
                    "US West".to_string(),
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
                    "EU Central".to_string(),
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
                .unwrap(),
        ))
    }

    #[tokio::test]
    async fn test_route_read_to_local() {
        let topology = create_test_topology_active_active().await;
        let router = Router::new(topology);

        let decision = router.route(RequestType::Read).await.unwrap();

        // Should route to local region (us-west-1)
        assert_eq!(decision.region_id, RegionId::new("us-west-1"));
        assert_eq!(decision.node_id, NodeId::new("node1"));
        assert_eq!(decision.endpoint, "localhost:50051");
    }

    #[tokio::test]
    async fn test_route_write_active_active() {
        let topology = create_test_topology_active_active().await;
        let router = Router::new(topology);

        let decision = router.route(RequestType::Write).await.unwrap();

        // In active-active, writes go to local region
        assert_eq!(decision.region_id, RegionId::new("us-west-1"));
        assert_eq!(decision.node_id, NodeId::new("node1"));
    }

    #[tokio::test]
    async fn test_route_write_primary_replica() {
        let topology = create_test_topology_primary_replica().await;
        let router = Router::new(topology);

        let decision = router.route(RequestType::Write).await.unwrap();

        // In primary-replica, writes go to primary (us-west-1)
        assert_eq!(decision.region_id, RegionId::new("us-west-1"));
        assert_eq!(decision.node_id, NodeId::new("node1"));
    }

    #[tokio::test]
    async fn test_route_read_primary_replica() {
        let topology = create_test_topology_primary_replica().await;
        let router = Router::new(topology);

        let decision = router.route(RequestType::Read).await.unwrap();

        // Reads go to local region even in primary-replica
        assert_eq!(decision.region_id, RegionId::new("us-west-1"));
    }

    #[tokio::test]
    async fn test_failover_when_local_unavailable() {
        let topology = create_test_topology_active_active().await;

        // Mark local region's node as unreachable
        {
            let mut topo = topology.write().await;
            if let Some(region) = topo.get_region_mut(&RegionId::new("us-west-1")) {
                if let Some(zone) = region.zones.get_mut(0) {
                    if let Some(node) = zone.nodes.get_mut(0) {
                        node.status = crate::topology::NodeStatus::Unreachable;
                    }
                }
            }
        }

        let router = Router::new(topology);
        let decision = router.route(RequestType::Read).await.unwrap();

        // Should failover to eu-central-1
        assert_eq!(decision.region_id, RegionId::new("eu-central-1"));
        assert_eq!(decision.node_id, NodeId::new("node2"));
    }

    #[tokio::test]
    async fn test_is_region_available() {
        let topology = create_test_topology_active_active().await;
        let router = Router::new(topology);

        assert!(router.is_region_available(&RegionId::new("us-west-1")).await);
        assert!(router.is_region_available(&RegionId::new("eu-central-1")).await);
        assert!(!router.is_region_available(&RegionId::new("non-existent")).await);
    }

    #[tokio::test]
    async fn test_get_available_regions() {
        let topology = create_test_topology_active_active().await;
        let router = Router::new(topology);

        let available = router.get_available_regions().await;

        assert_eq!(available.len(), 2);
        assert!(available.contains(&RegionId::new("us-west-1")));
        assert!(available.contains(&RegionId::new("eu-central-1")));
    }

    #[tokio::test]
    async fn test_no_healthy_nodes_error() {
        let topology = create_test_topology_active_active().await;

        // Mark all nodes as unreachable
        {
            let mut topo = topology.write().await;
            for region in &mut topo.regions {
                for zone in &mut region.zones {
                    for node in &mut zone.nodes {
                        node.status = crate::topology::NodeStatus::Unreachable;
                    }
                }
            }
        }

        let router = Router::new(topology);
        let result = router.route(RequestType::Read).await;

        assert!(result.is_err());
    }

    async fn create_test_topology_multiple_nodes() -> Arc<RwLock<Topology>> {
        Arc::new(RwLock::new(
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
                .add_region(RegionId::new("us-west-1"), "US West".to_string(), false)
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
                .add_node(
                    RegionId::new("us-west-1"),
                    ZoneId::new("us-west-1a"),
                    NodeId::new("node2"),
                    "localhost:50052".to_string(),
                )
                .add_node(
                    RegionId::new("us-west-1"),
                    ZoneId::new("us-west-1a"),
                    NodeId::new("node3"),
                    "localhost:50053".to_string(),
                )
                .build()
                .unwrap(),
        ))
    }

    #[tokio::test]
    async fn test_round_robin_load_balancing() {
        let topology = create_test_topology_multiple_nodes().await;
        let router = Router::new(topology); // Default is RoundRobin

        // Make multiple requests and verify round-robin distribution
        let decision1 = router.route(RequestType::Read).await.unwrap();
        let decision2 = router.route(RequestType::Read).await.unwrap();
        let decision3 = router.route(RequestType::Read).await.unwrap();
        let decision4 = router.route(RequestType::Read).await.unwrap();

        // Collect the node IDs
        let nodes: Vec<_> =
            vec![decision1.node_id, decision2.node_id, decision3.node_id, decision4.node_id];

        // Verify that requests are distributed (not all to the same node)
        // With 3 nodes, 4 requests should cycle through and hit at least 2 different nodes
        let unique_nodes: std::collections::HashSet<_> = nodes.iter().collect();
        assert!(
            unique_nodes.len() >= 2,
            "Round-robin should distribute across multiple nodes"
        );

        // Verify the round-robin pattern: node1, node2, node3, node1
        assert_eq!(nodes[0], NodeId::new("node1"));
        assert_eq!(nodes[1], NodeId::new("node2"));
        assert_eq!(nodes[2], NodeId::new("node3"));
        assert_eq!(nodes[3], NodeId::new("node1")); // Wraps around
    }

    #[tokio::test]
    async fn test_first_available_strategy() {
        let topology = create_test_topology_multiple_nodes().await;
        let router = Router::with_strategy(topology, LoadBalancingStrategy::FirstAvailable);

        // Make multiple requests - should all go to the same (first) node
        let decision1 = router.route(RequestType::Read).await.unwrap();
        let decision2 = router.route(RequestType::Read).await.unwrap();
        let decision3 = router.route(RequestType::Read).await.unwrap();

        // All should go to the first node
        assert_eq!(decision1.node_id, NodeId::new("node1"));
        assert_eq!(decision2.node_id, NodeId::new("node1"));
        assert_eq!(decision3.node_id, NodeId::new("node1"));
    }
}
