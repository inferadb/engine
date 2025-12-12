//! # Replication Topology
//!
//! Defines the multi-region replication topology including regions, zones,
//! replication strategies, and failure handling.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Unique identifier for a region
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);

impl RegionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RegionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a zone within a region
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ZoneId(pub String);

impl ZoneId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ZoneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a node (instance) within a zone
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a geographic region containing multiple zones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    /// Unique region identifier (e.g., "us-west-1", "eu-central-1")
    pub id: RegionId,
    /// Human-readable name
    pub name: String,
    /// Zones within this region
    pub zones: Vec<Zone>,
    /// Whether this is the primary region for writes
    pub is_primary: bool,
}

impl Region {
    pub fn new(id: RegionId, name: String, is_primary: bool) -> Self {
        Self { id, name, zones: Vec::new(), is_primary }
    }

    pub fn add_zone(&mut self, zone: Zone) {
        self.zones.push(zone);
    }

    pub fn get_zone(&self, zone_id: &ZoneId) -> Option<&Zone> {
        self.zones.iter().find(|z| &z.id == zone_id)
    }
}

/// Represents an availability zone within a region
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    /// Unique zone identifier (e.g., "us-west-1a")
    pub id: ZoneId,
    /// Human-readable name
    pub name: String,
    /// Nodes (instances) running in this zone
    pub nodes: Vec<Node>,
}

impl Zone {
    pub fn new(id: ZoneId, name: String) -> Self {
        Self { id, name, nodes: Vec::new() }
    }

    pub fn add_node(&mut self, node: Node) {
        self.nodes.push(node);
    }

    pub fn get_node(&self, node_id: &NodeId) -> Option<&Node> {
        self.nodes.iter().find(|n| &n.id == node_id)
    }
}

/// Represents a node (instance) running InferaDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Unique node identifier
    pub id: NodeId,
    /// gRPC endpoint for this node
    pub endpoint: String,
    /// Current health status
    pub status: NodeStatus,
    /// Last heartbeat timestamp (Unix milliseconds)
    pub last_heartbeat: u64,
}

impl Node {
    pub fn new(id: NodeId, endpoint: String) -> Self {
        Self { id, endpoint, status: NodeStatus::Healthy, last_heartbeat: 0 }
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self.status, NodeStatus::Healthy)
    }
}

/// Health status of a node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is healthy and accepting requests
    Healthy,
    /// Node is degraded but operational
    Degraded,
    /// Node is unreachable
    Unreachable,
}

/// Replication strategy determining how data is replicated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationStrategy {
    /// All regions can accept writes and resolve conflicts
    /// Best for: Global low-latency writes, high availability
    /// Trade-off: Must handle conflicts, more complex
    ActiveActive,

    /// One primary region accepts writes, others are read-only replicas
    /// Best for: Simpler conflict resolution, strong consistency
    /// Trade-off: Higher write latency for remote clients
    PrimaryReplica,

    /// Multiple regions can accept writes for different tenants/namespaces
    /// Best for: Data locality requirements, multi-tenant systems
    /// Trade-off: Requires partitioning strategy
    MultiMaster,
}

/// Complete replication topology configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    /// All regions in the topology
    pub regions: Vec<Region>,
    /// Replication strategy
    pub strategy: ReplicationStrategy,
    /// Replication targets: which regions replicate to which
    pub replication_graph: HashMap<RegionId, HashSet<RegionId>>,
    /// Local region for this node
    pub local_region: RegionId,
}

impl Topology {
    /// Create a new topology with the given strategy
    pub fn new(strategy: ReplicationStrategy, local_region: RegionId) -> Self {
        Self { regions: Vec::new(), strategy, replication_graph: HashMap::new(), local_region }
    }

    /// Add a region to the topology
    pub fn add_region(&mut self, region: Region) {
        self.regions.push(region);
    }

    /// Get a region by ID
    pub fn get_region(&self, region_id: &RegionId) -> Option<&Region> {
        self.regions.iter().find(|r| &r.id == region_id)
    }

    /// Get a mutable region by ID
    pub fn get_region_mut(&mut self, region_id: &RegionId) -> Option<&mut Region> {
        self.regions.iter_mut().find(|r| &r.id == region_id)
    }

    /// Get the primary region (for PrimaryReplica strategy)
    pub fn get_primary_region(&self) -> Option<&Region> {
        self.regions.iter().find(|r| r.is_primary)
    }

    /// Set replication targets for a region
    pub fn set_replication_targets(&mut self, source: RegionId, targets: HashSet<RegionId>) {
        self.replication_graph.insert(source, targets);
    }

    /// Get replication targets for a region
    pub fn get_replication_targets(&self, region_id: &RegionId) -> Vec<&RegionId> {
        self.replication_graph
            .get(region_id)
            .map(|targets| targets.iter().collect())
            .unwrap_or_default()
    }

    /// Get all healthy nodes in a region
    pub fn get_healthy_nodes(&self, region_id: &RegionId) -> Vec<&Node> {
        self.get_region(region_id)
            .map(|region| {
                region
                    .zones
                    .iter()
                    .flat_map(|zone| zone.nodes.iter())
                    .filter(|node| node.is_healthy())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if this is the local region
    pub fn is_local_region(&self, region_id: &RegionId) -> bool {
        &self.local_region == region_id
    }

    /// Validate the topology configuration
    pub fn validate(&self) -> Result<(), TopologyError> {
        // Check we have at least one region
        if self.regions.is_empty() {
            return Err(TopologyError::NoRegions);
        }

        // Check local region exists
        if self.get_region(&self.local_region).is_none() {
            return Err(TopologyError::InvalidLocalRegion(self.local_region.clone()));
        }

        // For PrimaryReplica, ensure exactly one primary
        if self.strategy == ReplicationStrategy::PrimaryReplica {
            let primary_count = self.regions.iter().filter(|r| r.is_primary).count();
            if primary_count == 0 {
                return Err(TopologyError::NoPrimaryRegion);
            }
            if primary_count > 1 {
                return Err(TopologyError::MultiplePrimaryRegions);
            }
        }

        // Validate replication graph references existing regions
        for (source, targets) in &self.replication_graph {
            if self.get_region(source).is_none() {
                return Err(TopologyError::InvalidReplicationSource(source.clone()));
            }
            for target in targets {
                if self.get_region(target).is_none() {
                    return Err(TopologyError::InvalidReplicationTarget(target.clone()));
                }
            }
        }

        Ok(())
    }
}

/// Errors related to topology configuration
#[derive(Debug, thiserror::Error)]
pub enum TopologyError {
    #[error("Topology has no regions")]
    NoRegions,

    #[error("Invalid local region: {0}")]
    InvalidLocalRegion(RegionId),

    #[error("PrimaryReplica strategy requires exactly one primary region, found none")]
    NoPrimaryRegion,

    #[error("PrimaryReplica strategy requires exactly one primary region, found multiple")]
    MultiplePrimaryRegions,

    #[error("Invalid replication source region: {0}")]
    InvalidReplicationSource(RegionId),

    #[error("Invalid replication target region: {0}")]
    InvalidReplicationTarget(RegionId),
}

/// Builder for creating topology configurations
pub struct TopologyBuilder {
    topology: Topology,
}

impl TopologyBuilder {
    /// Create a new topology builder
    pub fn new(strategy: ReplicationStrategy, local_region: RegionId) -> Self {
        Self { topology: Topology::new(strategy, local_region) }
    }

    /// Add a region with zones and nodes
    pub fn add_region(mut self, region_id: RegionId, name: String, is_primary: bool) -> Self {
        let region = Region::new(region_id, name, is_primary);
        self.topology.add_region(region);
        self
    }

    /// Add a zone to a region
    pub fn add_zone(mut self, region_id: RegionId, zone_id: ZoneId, name: String) -> Self {
        if let Some(region) = self.topology.get_region_mut(&region_id) {
            region.add_zone(Zone::new(zone_id, name));
        }
        self
    }

    /// Add a node to a zone
    pub fn add_node(
        mut self,
        region_id: RegionId,
        zone_id: ZoneId,
        node_id: NodeId,
        endpoint: String,
    ) -> Self {
        if let Some(region) = self.topology.get_region_mut(&region_id) {
            if let Some(zone) = region.zones.iter_mut().find(|z| z.id == zone_id) {
                zone.add_node(Node::new(node_id, endpoint));
            }
        }
        self
    }

    /// Set replication targets for a region (which regions it replicates to)
    pub fn set_replication_targets(mut self, source: RegionId, targets: Vec<RegionId>) -> Self {
        self.topology.set_replication_targets(source, targets.into_iter().collect());
        self
    }

    /// Build and validate the topology
    pub fn build(self) -> Result<Topology, TopologyError> {
        self.topology.validate()?;
        Ok(self.topology)
    }
}

/// Event type for topology changes
#[derive(Debug, Clone)]
pub enum TopologyEvent {
    /// A node was added
    NodeAdded { region_id: RegionId, zone_id: ZoneId, node: Node },
    /// A node was removed
    NodeRemoved { region_id: RegionId, zone_id: ZoneId, node_id: NodeId },
    /// A node's status changed
    NodeStatusChanged { region_id: RegionId, zone_id: ZoneId, node_id: NodeId, status: NodeStatus },
    /// A region was added
    RegionAdded { region: Region },
    /// A region was removed
    RegionRemoved { region_id: RegionId },
    /// The entire topology was replaced
    TopologyReplaced,
}

/// Manager for topology with runtime update support
///
/// Provides methods to update the topology at runtime and notify
/// subscribers of changes.
pub struct TopologyManager {
    topology: std::sync::Arc<tokio::sync::RwLock<Topology>>,
    event_tx: tokio::sync::broadcast::Sender<TopologyEvent>,
}

impl TopologyManager {
    /// Create a new topology manager
    pub fn new(topology: Topology) -> Self {
        let (event_tx, _) = tokio::sync::broadcast::channel(64);
        Self { topology: std::sync::Arc::new(tokio::sync::RwLock::new(topology)), event_tx }
    }

    /// Get a shared reference to the topology
    pub fn topology(&self) -> std::sync::Arc<tokio::sync::RwLock<Topology>> {
        self.topology.clone()
    }

    /// Subscribe to topology change events
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<TopologyEvent> {
        self.event_tx.subscribe()
    }

    /// Update a node's status
    pub async fn update_node_status(
        &self,
        region_id: &RegionId,
        zone_id: &ZoneId,
        node_id: &NodeId,
        status: NodeStatus,
    ) -> Result<(), TopologyError> {
        let mut topology = self.topology.write().await;

        let region = topology
            .get_region_mut(region_id)
            .ok_or_else(|| TopologyError::InvalidLocalRegion(region_id.clone()))?;

        let zone = region.zones.iter_mut().find(|z| &z.id == zone_id).ok_or_else(|| {
            TopologyError::InvalidReplicationSource(RegionId::new(zone_id.as_str()))
        })?;

        let node = zone.nodes.iter_mut().find(|n| &n.id == node_id).ok_or_else(|| {
            TopologyError::InvalidReplicationTarget(RegionId::new(node_id.as_str()))
        })?;

        let old_status = node.status;
        node.status = status;
        node.last_heartbeat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Only emit event if status actually changed
        if old_status != status {
            let _ = self.event_tx.send(TopologyEvent::NodeStatusChanged {
                region_id: region_id.clone(),
                zone_id: zone_id.clone(),
                node_id: node_id.clone(),
                status,
            });
        }

        Ok(())
    }

    /// Add a new node to a zone
    pub async fn add_node(
        &self,
        region_id: &RegionId,
        zone_id: &ZoneId,
        node: Node,
    ) -> Result<(), TopologyError> {
        let mut topology = self.topology.write().await;

        let region = topology
            .get_region_mut(region_id)
            .ok_or_else(|| TopologyError::InvalidLocalRegion(region_id.clone()))?;

        let zone = region.zones.iter_mut().find(|z| &z.id == zone_id).ok_or_else(|| {
            TopologyError::InvalidReplicationSource(RegionId::new(zone_id.as_str()))
        })?;

        // Check if node already exists
        if zone.nodes.iter().any(|n| n.id == node.id) {
            return Ok(()); // Node already exists, no-op
        }

        let event = TopologyEvent::NodeAdded {
            region_id: region_id.clone(),
            zone_id: zone_id.clone(),
            node: node.clone(),
        };

        zone.add_node(node);
        let _ = self.event_tx.send(event);

        Ok(())
    }

    /// Remove a node from a zone
    pub async fn remove_node(
        &self,
        region_id: &RegionId,
        zone_id: &ZoneId,
        node_id: &NodeId,
    ) -> Result<(), TopologyError> {
        let mut topology = self.topology.write().await;

        let region = topology
            .get_region_mut(region_id)
            .ok_or_else(|| TopologyError::InvalidLocalRegion(region_id.clone()))?;

        let zone = region.zones.iter_mut().find(|z| &z.id == zone_id).ok_or_else(|| {
            TopologyError::InvalidReplicationSource(RegionId::new(zone_id.as_str()))
        })?;

        let original_len = zone.nodes.len();
        zone.nodes.retain(|n| &n.id != node_id);

        // Only emit event if node was actually removed
        if zone.nodes.len() < original_len {
            let _ = self.event_tx.send(TopologyEvent::NodeRemoved {
                region_id: region_id.clone(),
                zone_id: zone_id.clone(),
                node_id: node_id.clone(),
            });
        }

        Ok(())
    }

    /// Replace the entire topology
    pub async fn replace_topology(&self, new_topology: Topology) -> Result<(), TopologyError> {
        new_topology.validate()?;

        let mut topology = self.topology.write().await;
        *topology = new_topology;

        let _ = self.event_tx.send(TopologyEvent::TopologyReplaced);

        Ok(())
    }

    /// Mark a node as healthy based on a heartbeat
    pub async fn record_heartbeat(
        &self,
        region_id: &RegionId,
        zone_id: &ZoneId,
        node_id: &NodeId,
    ) -> Result<(), TopologyError> {
        self.update_node_status(region_id, zone_id, node_id, NodeStatus::Healthy).await
    }

    /// Check for stale nodes and mark them as unreachable
    ///
    /// A node is considered stale if it hasn't sent a heartbeat
    /// within the specified timeout (in milliseconds).
    pub async fn check_stale_nodes(&self, timeout_ms: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut topology = self.topology.write().await;

        for region in &mut topology.regions {
            for zone in &mut region.zones {
                for node in &mut zone.nodes {
                    if node.status == NodeStatus::Healthy && node.last_heartbeat > 0 {
                        let elapsed = now.saturating_sub(node.last_heartbeat);
                        if elapsed > timeout_ms {
                            let old_status = node.status;
                            node.status = NodeStatus::Unreachable;

                            if old_status != NodeStatus::Unreachable {
                                let _ = self.event_tx.send(TopologyEvent::NodeStatusChanged {
                                    region_id: region.id.clone(),
                                    zone_id: zone.id.clone(),
                                    node_id: node.id.clone(),
                                    status: NodeStatus::Unreachable,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_active_topology() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
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
                .add_region(RegionId::new("eu-central-1"), "EU Central 1".to_string(), false)
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

        assert_eq!(topology.regions.len(), 2);
        assert_eq!(topology.strategy, ReplicationStrategy::ActiveActive);
        assert_eq!(topology.local_region, RegionId::new("us-west-1"));
    }

    #[test]
    fn test_primary_replica_topology() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::PrimaryReplica, RegionId::new("us-west-1"))
                .add_region(RegionId::new("us-west-1"), "US West 1".to_string(), true)
                .add_region(RegionId::new("eu-central-1"), "EU Central 1".to_string(), false)
                .set_replication_targets(
                    RegionId::new("us-west-1"),
                    vec![RegionId::new("eu-central-1")],
                )
                .build()
                .unwrap();

        assert_eq!(topology.get_primary_region().unwrap().id, RegionId::new("us-west-1"));
    }

    #[test]
    fn test_topology_validation_no_regions() {
        let topology = Topology::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"));
        assert!(matches!(topology.validate(), Err(TopologyError::NoRegions)));
    }

    #[test]
    fn test_topology_validation_invalid_local_region() {
        let mut topology =
            Topology::new(ReplicationStrategy::ActiveActive, RegionId::new("invalid"));
        topology.add_region(Region::new(
            RegionId::new("us-west-1"),
            "US West 1".to_string(),
            false,
        ));
        assert!(matches!(topology.validate(), Err(TopologyError::InvalidLocalRegion(_))));
    }

    #[test]
    fn test_topology_validation_no_primary() {
        let mut topology =
            Topology::new(ReplicationStrategy::PrimaryReplica, RegionId::new("us-west-1"));
        topology.add_region(Region::new(
            RegionId::new("us-west-1"),
            "US West 1".to_string(),
            false,
        ));
        assert!(matches!(topology.validate(), Err(TopologyError::NoPrimaryRegion)));
    }

    #[test]
    fn test_topology_validation_multiple_primary() {
        let mut topology =
            Topology::new(ReplicationStrategy::PrimaryReplica, RegionId::new("us-west-1"));
        topology.add_region(Region::new(RegionId::new("us-west-1"), "US West 1".to_string(), true));
        topology.add_region(Region::new(
            RegionId::new("eu-central-1"),
            "EU Central 1".to_string(),
            true,
        ));
        assert!(matches!(topology.validate(), Err(TopologyError::MultiplePrimaryRegions)));
    }

    #[test]
    fn test_get_healthy_nodes() {
        let mut topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
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
                .build()
                .unwrap();

        let healthy = topology.get_healthy_nodes(&RegionId::new("us-west-1"));
        assert_eq!(healthy.len(), 1);

        // Mark node as unreachable
        if let Some(region) = topology.get_region_mut(&RegionId::new("us-west-1")) {
            if let Some(zone) = region.zones.get_mut(0) {
                if let Some(node) = zone.nodes.get_mut(0) {
                    node.status = NodeStatus::Unreachable;
                }
            }
        }

        let healthy = topology.get_healthy_nodes(&RegionId::new("us-west-1"));
        assert_eq!(healthy.len(), 0);
    }

    #[test]
    fn test_replication_graph() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
                .add_region(RegionId::new("us-west-1"), "US West 1".to_string(), false)
                .add_region(RegionId::new("eu-central-1"), "EU Central 1".to_string(), false)
                .add_region(RegionId::new("ap-southeast-1"), "AP Southeast 1".to_string(), false)
                .set_replication_targets(
                    RegionId::new("us-west-1"),
                    vec![RegionId::new("eu-central-1"), RegionId::new("ap-southeast-1")],
                )
                .build()
                .unwrap();

        let targets = topology.get_replication_targets(&RegionId::new("us-west-1"));
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&&RegionId::new("eu-central-1")));
        assert!(targets.contains(&&RegionId::new("ap-southeast-1")));
    }

    #[tokio::test]
    async fn test_topology_manager_update_node_status() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
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
                .build()
                .unwrap();

        let manager = TopologyManager::new(topology);
        let mut rx = manager.subscribe();

        // Update status to Unreachable
        manager
            .update_node_status(
                &RegionId::new("us-west-1"),
                &ZoneId::new("us-west-1a"),
                &NodeId::new("node1"),
                NodeStatus::Unreachable,
            )
            .await
            .unwrap();

        // Verify event was sent
        let event = rx.try_recv().unwrap();
        match event {
            TopologyEvent::NodeStatusChanged { node_id, status, .. } => {
                assert_eq!(node_id, NodeId::new("node1"));
                assert_eq!(status, NodeStatus::Unreachable);
            },
            _ => panic!("Expected NodeStatusChanged event"),
        }

        // Verify status was updated
        let topo = manager.topology.read().await;
        let node = topo
            .get_region(&RegionId::new("us-west-1"))
            .unwrap()
            .get_zone(&ZoneId::new("us-west-1a"))
            .unwrap()
            .get_node(&NodeId::new("node1"))
            .unwrap();
        assert_eq!(node.status, NodeStatus::Unreachable);
    }

    #[tokio::test]
    async fn test_topology_manager_add_node() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
                .add_region(RegionId::new("us-west-1"), "US West 1".to_string(), false)
                .add_zone(
                    RegionId::new("us-west-1"),
                    ZoneId::new("us-west-1a"),
                    "Zone A".to_string(),
                )
                .build()
                .unwrap();

        let manager = TopologyManager::new(topology);
        let mut rx = manager.subscribe();

        // Add a new node
        let new_node = Node::new(NodeId::new("node1"), "localhost:50051".to_string());
        manager
            .add_node(&RegionId::new("us-west-1"), &ZoneId::new("us-west-1a"), new_node)
            .await
            .unwrap();

        // Verify event was sent
        let event = rx.try_recv().unwrap();
        match event {
            TopologyEvent::NodeAdded { node, .. } => {
                assert_eq!(node.id, NodeId::new("node1"));
            },
            _ => panic!("Expected NodeAdded event"),
        }

        // Verify node was added
        let topo = manager.topology.read().await;
        let zone = topo
            .get_region(&RegionId::new("us-west-1"))
            .unwrap()
            .get_zone(&ZoneId::new("us-west-1a"))
            .unwrap();
        assert_eq!(zone.nodes.len(), 1);
    }

    #[tokio::test]
    async fn test_topology_manager_remove_node() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
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
                .build()
                .unwrap();

        let manager = TopologyManager::new(topology);
        let mut rx = manager.subscribe();

        // Remove the node
        manager
            .remove_node(
                &RegionId::new("us-west-1"),
                &ZoneId::new("us-west-1a"),
                &NodeId::new("node1"),
            )
            .await
            .unwrap();

        // Verify event was sent
        let event = rx.try_recv().unwrap();
        match event {
            TopologyEvent::NodeRemoved { node_id, .. } => {
                assert_eq!(node_id, NodeId::new("node1"));
            },
            _ => panic!("Expected NodeRemoved event"),
        }

        // Verify node was removed
        let topo = manager.topology.read().await;
        let zone = topo
            .get_region(&RegionId::new("us-west-1"))
            .unwrap()
            .get_zone(&ZoneId::new("us-west-1a"))
            .unwrap();
        assert!(zone.nodes.is_empty());
    }

    #[tokio::test]
    async fn test_topology_manager_replace_topology() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
                .add_region(RegionId::new("us-west-1"), "US West 1".to_string(), false)
                .build()
                .unwrap();

        let manager = TopologyManager::new(topology);
        let mut rx = manager.subscribe();

        // Create a new topology
        let new_topology = TopologyBuilder::new(
            ReplicationStrategy::PrimaryReplica,
            RegionId::new("eu-central-1"),
        )
        .add_region(RegionId::new("eu-central-1"), "EU Central 1".to_string(), true)
        .build()
        .unwrap();

        // Replace the topology
        manager.replace_topology(new_topology).await.unwrap();

        // Verify event was sent
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, TopologyEvent::TopologyReplaced));

        // Verify topology was replaced
        let topo = manager.topology.read().await;
        assert_eq!(topo.strategy, ReplicationStrategy::PrimaryReplica);
        assert_eq!(topo.local_region, RegionId::new("eu-central-1"));
    }

    #[tokio::test]
    async fn test_topology_manager_record_heartbeat() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
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
                .build()
                .unwrap();

        let manager = TopologyManager::new(topology);

        // Record heartbeat
        manager
            .record_heartbeat(
                &RegionId::new("us-west-1"),
                &ZoneId::new("us-west-1a"),
                &NodeId::new("node1"),
            )
            .await
            .unwrap();

        // Verify heartbeat was recorded
        let topo = manager.topology.read().await;
        let node = topo
            .get_region(&RegionId::new("us-west-1"))
            .unwrap()
            .get_zone(&ZoneId::new("us-west-1a"))
            .unwrap()
            .get_node(&NodeId::new("node1"))
            .unwrap();
        assert!(node.last_heartbeat > 0);
    }

    #[tokio::test]
    async fn test_topology_manager_check_stale_nodes() {
        let mut topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
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
                .build()
                .unwrap();

        // Set an old heartbeat (1 second ago)
        if let Some(region) = topology.get_region_mut(&RegionId::new("us-west-1")) {
            if let Some(zone) = region.zones.get_mut(0) {
                if let Some(node) = zone.nodes.get_mut(0) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    node.last_heartbeat = now - 2000; // 2 seconds ago
                }
            }
        }

        let manager = TopologyManager::new(topology);
        let mut rx = manager.subscribe();

        // Check for stale nodes with 1 second timeout
        manager.check_stale_nodes(1000).await;

        // Verify event was sent
        let event = rx.try_recv().unwrap();
        match event {
            TopologyEvent::NodeStatusChanged { node_id, status, .. } => {
                assert_eq!(node_id, NodeId::new("node1"));
                assert_eq!(status, NodeStatus::Unreachable);
            },
            _ => panic!("Expected NodeStatusChanged event"),
        }

        // Verify node is now unreachable
        let topo = manager.topology.read().await;
        let node = topo
            .get_region(&RegionId::new("us-west-1"))
            .unwrap()
            .get_zone(&ZoneId::new("us-west-1a"))
            .unwrap()
            .get_node(&NodeId::new("node1"))
            .unwrap();
        assert_eq!(node.status, NodeStatus::Unreachable);
    }

    #[tokio::test]
    async fn test_topology_manager_no_duplicate_events() {
        let topology =
            TopologyBuilder::new(ReplicationStrategy::ActiveActive, RegionId::new("us-west-1"))
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
                .build()
                .unwrap();

        let manager = TopologyManager::new(topology);
        let mut rx = manager.subscribe();

        // Update to Healthy (same as current status)
        manager
            .update_node_status(
                &RegionId::new("us-west-1"),
                &ZoneId::new("us-west-1a"),
                &NodeId::new("node1"),
                NodeStatus::Healthy,
            )
            .await
            .unwrap();

        // Should not receive an event since status didn't change
        assert!(rx.try_recv().is_err());
    }
}
