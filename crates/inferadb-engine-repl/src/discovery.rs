//! # Discovery Integration
//!
//! Bridges service discovery (Tailscale/Kubernetes) with replication topology.
//! Enables automatic topology construction from discovered endpoints.

use std::collections::HashSet;

use tracing::{debug, info, warn};

use crate::{
    Node, NodeId, NodeStatus, RegionId, ReplicationStrategy, Result, Topology, TopologyBuilder,
    ZoneId,
    topology::TopologyManager,
};

/// Configuration for building topology from discovery
#[derive(Debug, Clone)]
pub struct DiscoveryTopologyConfig {
    /// Local region/cluster identifier
    pub local_region: String,
    /// Replication strategy to use
    pub strategy: ReplicationStrategy,
    /// Default zone name for discovered nodes
    pub default_zone: String,
}

impl Default for DiscoveryTopologyConfig {
    fn default() -> Self {
        Self {
            local_region: "local".to_string(),
            strategy: ReplicationStrategy::ActiveActive,
            default_zone: "default".to_string(),
        }
    }
}

/// Discovered endpoint with region metadata
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    /// Endpoint URL
    pub url: String,
    /// Region/cluster this endpoint belongs to
    pub region: String,
    /// Optional zone within the region
    pub zone: Option<String>,
    /// Node identifier (derived from URL or pod name)
    pub node_id: String,
    /// Whether the endpoint is healthy
    pub healthy: bool,
}

impl DiscoveredEndpoint {
    /// Create a new discovered endpoint
    pub fn new(url: String, region: String, node_id: String) -> Self {
        Self { url, region, zone: None, node_id, healthy: true }
    }

    /// Set the zone
    pub fn with_zone(mut self, zone: String) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Set health status
    pub fn with_health(mut self, healthy: bool) -> Self {
        self.healthy = healthy;
        self
    }
}

/// Builds a replication topology from discovered endpoints
pub struct TopologyFromDiscovery {
    config: DiscoveryTopologyConfig,
    endpoints: Vec<DiscoveredEndpoint>,
}

impl TopologyFromDiscovery {
    /// Create a new topology builder from discovery config
    pub fn new(config: DiscoveryTopologyConfig) -> Self {
        Self { config, endpoints: Vec::new() }
    }

    /// Add a discovered endpoint
    pub fn add_endpoint(&mut self, endpoint: DiscoveredEndpoint) {
        self.endpoints.push(endpoint);
    }

    /// Add multiple discovered endpoints
    pub fn add_endpoints(&mut self, endpoints: impl IntoIterator<Item = DiscoveredEndpoint>) {
        self.endpoints.extend(endpoints);
    }

    /// Build the topology from discovered endpoints
    pub fn build(self) -> Result<Topology> {
        let mut builder = TopologyBuilder::new(
            self.config.strategy,
            RegionId::new(&self.config.local_region),
        );

        // Group endpoints by region
        let mut regions: std::collections::HashMap<String, Vec<DiscoveredEndpoint>> =
            std::collections::HashMap::new();

        for endpoint in self.endpoints {
            regions.entry(endpoint.region.clone()).or_default().push(endpoint);
        }

        // Determine which is the primary region (for PrimaryReplica strategy)
        let is_primary = |region: &str| -> bool {
            match self.config.strategy {
                ReplicationStrategy::PrimaryReplica => region == self.config.local_region,
                _ => false,
            }
        };

        // Build regions
        let mut region_ids: Vec<RegionId> = Vec::new();

        for (region_name, endpoints) in &regions {
            let region_id = RegionId::new(region_name);
            region_ids.push(region_id.clone());

            builder = builder.add_region(
                region_id.clone(),
                format!("{} Region", region_name),
                is_primary(region_name),
            );

            // Group endpoints by zone within region
            let mut zones: std::collections::HashMap<String, Vec<&DiscoveredEndpoint>> =
                std::collections::HashMap::new();

            for endpoint in endpoints {
                let zone_name =
                    endpoint.zone.as_ref().unwrap_or(&self.config.default_zone).clone();
                zones.entry(zone_name).or_default().push(endpoint);
            }

            // Add zones and nodes
            for (zone_name, zone_endpoints) in zones {
                let zone_id = ZoneId::new(&zone_name);

                builder =
                    builder.add_zone(region_id.clone(), zone_id.clone(), zone_name.clone());

                for endpoint in zone_endpoints {
                    let node_id = NodeId::new(&endpoint.node_id);

                    builder = builder.add_node(
                        region_id.clone(),
                        zone_id.clone(),
                        node_id,
                        endpoint.url.clone(),
                    );

                    debug!(
                        region = %region_name,
                        zone = %zone_name,
                        node = %endpoint.node_id,
                        url = %endpoint.url,
                        "Added node to topology"
                    );
                }
            }
        }

        // Set up replication graph based on strategy
        let local_region_id = RegionId::new(&self.config.local_region);

        match self.config.strategy {
            ReplicationStrategy::ActiveActive => {
                // All regions replicate to all other regions
                for source in &region_ids {
                    let targets: Vec<RegionId> =
                        region_ids.iter().filter(|r| *r != source).cloned().collect();
                    if !targets.is_empty() {
                        builder = builder.set_replication_targets(source.clone(), targets);
                    }
                }
            },
            ReplicationStrategy::PrimaryReplica => {
                // Primary replicates to all replicas
                let replica_ids: Vec<RegionId> =
                    region_ids.iter().filter(|r| *r != &local_region_id).cloned().collect();
                if !replica_ids.is_empty() {
                    builder =
                        builder.set_replication_targets(local_region_id.clone(), replica_ids);
                }
            },
            ReplicationStrategy::MultiMaster => {
                // Each region replicates to its configured targets
                // For now, replicate to all other regions
                for source in &region_ids {
                    let targets: Vec<RegionId> =
                        region_ids.iter().filter(|r| *r != source).cloned().collect();
                    if !targets.is_empty() {
                        builder = builder.set_replication_targets(source.clone(), targets);
                    }
                }
            },
        }

        let topology = builder.build().map_err(|e| {
            crate::ReplError::Replication(format!("Failed to build topology: {}", e))
        })?;

        info!(
            regions = region_ids.len(),
            strategy = ?self.config.strategy,
            local_region = %self.config.local_region,
            "Built replication topology from discovery"
        );

        Ok(topology)
    }
}

/// Update an existing TopologyManager with newly discovered endpoints
pub async fn update_topology_from_discovery(
    manager: &TopologyManager,
    endpoints: Vec<DiscoveredEndpoint>,
    default_zone: &str,
) {
    let topology = manager.topology();
    let topology_read = topology.read().await;

    // Get existing regions
    let existing_regions: HashSet<String> =
        topology_read.regions.iter().map(|r| r.id.0.clone()).collect();

    // Track which endpoints we've seen
    let mut seen_nodes: HashSet<(String, String, String)> = HashSet::new();

    drop(topology_read);

    for endpoint in endpoints {
        let region_id = RegionId::new(&endpoint.region);
        let zone_id = ZoneId::new(endpoint.zone.as_deref().unwrap_or(default_zone));
        let node_id = NodeId::new(&endpoint.node_id);

        seen_nodes.insert((endpoint.region.clone(), zone_id.0.clone(), endpoint.node_id.clone()));

        // Check if region exists
        if !existing_regions.contains(&endpoint.region) {
            warn!(
                region = %endpoint.region,
                "Discovered endpoint in unknown region, skipping"
            );
            continue;
        }

        // Try to update node status or add new node
        let status = if endpoint.healthy { NodeStatus::Healthy } else { NodeStatus::Unreachable };

        let update_result =
            manager.update_node_status(&region_id, &zone_id, &node_id, status).await;

        if update_result.is_err() {
            // Node doesn't exist, try to add it
            let node = Node::new(node_id, endpoint.url);
            if let Err(e) = manager.add_node(&region_id, &zone_id, node).await {
                warn!(
                    error = %e,
                    region = %endpoint.region,
                    node = %endpoint.node_id,
                    "Failed to add discovered node"
                );
            } else {
                info!(
                    region = %endpoint.region,
                    node = %endpoint.node_id,
                    "Added new node from discovery"
                );
            }
        }
    }

    debug!(
        nodes_processed = seen_nodes.len(),
        "Processed discovered endpoints"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_topology_config_default() {
        let config = DiscoveryTopologyConfig::default();
        assert_eq!(config.local_region, "local");
        assert_eq!(config.strategy, ReplicationStrategy::ActiveActive);
        assert_eq!(config.default_zone, "default");
    }

    #[test]
    fn test_discovered_endpoint_creation() {
        let endpoint = DiscoveredEndpoint::new(
            "http://localhost:8080".to_string(),
            "us-west-1".to_string(),
            "node1".to_string(),
        )
        .with_zone("us-west-1a".to_string())
        .with_health(true);

        assert_eq!(endpoint.url, "http://localhost:8080");
        assert_eq!(endpoint.region, "us-west-1");
        assert_eq!(endpoint.zone, Some("us-west-1a".to_string()));
        assert_eq!(endpoint.node_id, "node1");
        assert!(endpoint.healthy);
    }

    #[test]
    fn test_build_single_region_topology() {
        let config = DiscoveryTopologyConfig {
            local_region: "us-west-1".to_string(),
            strategy: ReplicationStrategy::ActiveActive,
            default_zone: "default".to_string(),
        };

        let mut builder = TopologyFromDiscovery::new(config);

        builder.add_endpoint(DiscoveredEndpoint::new(
            "http://10.0.0.1:8080".to_string(),
            "us-west-1".to_string(),
            "node1".to_string(),
        ));

        builder.add_endpoint(DiscoveredEndpoint::new(
            "http://10.0.0.2:8080".to_string(),
            "us-west-1".to_string(),
            "node2".to_string(),
        ));

        let topology = builder.build().unwrap();

        assert_eq!(topology.regions.len(), 1);
        assert_eq!(topology.local_region, RegionId::new("us-west-1"));

        let region = topology.get_region(&RegionId::new("us-west-1")).unwrap();
        assert_eq!(region.zones.len(), 1);
        assert_eq!(region.zones[0].nodes.len(), 2);
    }

    #[test]
    fn test_build_multi_region_topology() {
        let config = DiscoveryTopologyConfig {
            local_region: "us-west-1".to_string(),
            strategy: ReplicationStrategy::ActiveActive,
            default_zone: "default".to_string(),
        };

        let mut builder = TopologyFromDiscovery::new(config);

        // US West nodes
        builder.add_endpoint(
            DiscoveredEndpoint::new(
                "http://10.0.0.1:8080".to_string(),
                "us-west-1".to_string(),
                "node1".to_string(),
            )
            .with_zone("us-west-1a".to_string()),
        );

        // EU Central nodes
        builder.add_endpoint(
            DiscoveredEndpoint::new(
                "http://10.1.0.1:8080".to_string(),
                "eu-central-1".to_string(),
                "node2".to_string(),
            )
            .with_zone("eu-central-1a".to_string()),
        );

        let topology = builder.build().unwrap();

        assert_eq!(topology.regions.len(), 2);
        assert_eq!(topology.strategy, ReplicationStrategy::ActiveActive);

        // Check replication graph - both should replicate to each other
        let us_targets = topology.get_replication_targets(&RegionId::new("us-west-1"));
        assert_eq!(us_targets.len(), 1);
        assert!(us_targets.contains(&&RegionId::new("eu-central-1")));

        let eu_targets = topology.get_replication_targets(&RegionId::new("eu-central-1"));
        assert_eq!(eu_targets.len(), 1);
        assert!(eu_targets.contains(&&RegionId::new("us-west-1")));
    }

    #[test]
    fn test_build_primary_replica_topology() {
        let config = DiscoveryTopologyConfig {
            local_region: "us-west-1".to_string(),
            strategy: ReplicationStrategy::PrimaryReplica,
            default_zone: "default".to_string(),
        };

        let mut builder = TopologyFromDiscovery::new(config);

        builder.add_endpoint(DiscoveredEndpoint::new(
            "http://10.0.0.1:8080".to_string(),
            "us-west-1".to_string(),
            "primary".to_string(),
        ));

        builder.add_endpoint(DiscoveredEndpoint::new(
            "http://10.1.0.1:8080".to_string(),
            "eu-central-1".to_string(),
            "replica".to_string(),
        ));

        let topology = builder.build().unwrap();

        // Primary should replicate to replica
        let primary = topology.get_primary_region().unwrap();
        assert_eq!(primary.id, RegionId::new("us-west-1"));
        assert!(primary.is_primary);

        let targets = topology.get_replication_targets(&RegionId::new("us-west-1"));
        assert_eq!(targets.len(), 1);
        assert!(targets.contains(&&RegionId::new("eu-central-1")));

        // Replica should not replicate anywhere
        let replica_targets = topology.get_replication_targets(&RegionId::new("eu-central-1"));
        assert!(replica_targets.is_empty());
    }

    #[tokio::test]
    async fn test_update_topology_from_discovery() {
        // Create initial topology
        let topology = TopologyBuilder::new(
            ReplicationStrategy::ActiveActive,
            RegionId::new("us-west-1"),
        )
        .add_region(RegionId::new("us-west-1"), "US West".to_string(), false)
        .add_zone(RegionId::new("us-west-1"), ZoneId::new("default"), "Default".to_string())
        .add_node(
            RegionId::new("us-west-1"),
            ZoneId::new("default"),
            NodeId::new("node1"),
            "http://10.0.0.1:8080".to_string(),
        )
        .build()
        .unwrap();

        let manager = TopologyManager::new(topology);

        // Update with discovered endpoints
        let endpoints = vec![DiscoveredEndpoint::new(
            "http://10.0.0.1:8080".to_string(),
            "us-west-1".to_string(),
            "node1".to_string(),
        )
        .with_health(false)];

        update_topology_from_discovery(&manager, endpoints, "default").await;

        // Check that the node status was updated
        let topology_arc = manager.topology();
        let topo = topology_arc.read().await;
        let node = topo
            .get_region(&RegionId::new("us-west-1"))
            .unwrap()
            .get_zone(&ZoneId::new("default"))
            .unwrap()
            .get_node(&NodeId::new("node1"))
            .unwrap();

        assert_eq!(node.status, NodeStatus::Unreachable);
    }
}
