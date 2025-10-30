//! # Replication Topology
//!
//! Defines the multi-region replication topology including regions, zones,
//! replication strategies, and failure handling.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
        Self {
            id,
            name,
            zones: Vec::new(),
            is_primary,
        }
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
        Self {
            id,
            name,
            nodes: Vec::new(),
        }
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
        Self {
            id,
            endpoint,
            status: NodeStatus::Healthy,
            last_heartbeat: 0,
        }
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
        Self {
            regions: Vec::new(),
            strategy,
            replication_graph: HashMap::new(),
            local_region,
        }
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
        Self {
            topology: Topology::new(strategy, local_region),
        }
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
        self.topology
            .set_replication_targets(source, targets.into_iter().collect());
        self
    }

    /// Build and validate the topology
    pub fn build(self) -> Result<Topology, TopologyError> {
        self.topology.validate()?;
        Ok(self.topology)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_active_topology() {
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

        assert_eq!(topology.regions.len(), 2);
        assert_eq!(topology.strategy, ReplicationStrategy::ActiveActive);
        assert_eq!(topology.local_region, RegionId::new("us-west-1"));
    }

    #[test]
    fn test_primary_replica_topology() {
        let topology = TopologyBuilder::new(
            ReplicationStrategy::PrimaryReplica,
            RegionId::new("us-west-1"),
        )
        .add_region(RegionId::new("us-west-1"), "US West 1".to_string(), true)
        .add_region(
            RegionId::new("eu-central-1"),
            "EU Central 1".to_string(),
            false,
        )
        .set_replication_targets(
            RegionId::new("us-west-1"),
            vec![RegionId::new("eu-central-1")],
        )
        .build()
        .unwrap();

        assert_eq!(
            topology.get_primary_region().unwrap().id,
            RegionId::new("us-west-1")
        );
    }

    #[test]
    fn test_topology_validation_no_regions() {
        let topology = Topology::new(
            ReplicationStrategy::ActiveActive,
            RegionId::new("us-west-1"),
        );
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
        assert!(matches!(
            topology.validate(),
            Err(TopologyError::InvalidLocalRegion(_))
        ));
    }

    #[test]
    fn test_topology_validation_no_primary() {
        let mut topology = Topology::new(
            ReplicationStrategy::PrimaryReplica,
            RegionId::new("us-west-1"),
        );
        topology.add_region(Region::new(
            RegionId::new("us-west-1"),
            "US West 1".to_string(),
            false,
        ));
        assert!(matches!(
            topology.validate(),
            Err(TopologyError::NoPrimaryRegion)
        ));
    }

    #[test]
    fn test_topology_validation_multiple_primary() {
        let mut topology = Topology::new(
            ReplicationStrategy::PrimaryReplica,
            RegionId::new("us-west-1"),
        );
        topology.add_region(Region::new(
            RegionId::new("us-west-1"),
            "US West 1".to_string(),
            true,
        ));
        topology.add_region(Region::new(
            RegionId::new("eu-central-1"),
            "EU Central 1".to_string(),
            true,
        ));
        assert!(matches!(
            topology.validate(),
            Err(TopologyError::MultiplePrimaryRegions)
        ));
    }

    #[test]
    fn test_get_healthy_nodes() {
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
        let topology = TopologyBuilder::new(
            ReplicationStrategy::ActiveActive,
            RegionId::new("us-west-1"),
        )
        .add_region(RegionId::new("us-west-1"), "US West 1".to_string(), false)
        .add_region(
            RegionId::new("eu-central-1"),
            "EU Central 1".to_string(),
            false,
        )
        .add_region(
            RegionId::new("ap-southeast-1"),
            "AP Southeast 1".to_string(),
            false,
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

        let targets = topology.get_replication_targets(&RegionId::new("us-west-1"));
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&&RegionId::new("eu-central-1")));
        assert!(targets.contains(&&RegionId::new("ap-southeast-1")));
    }
}
