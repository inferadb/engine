//! Configuration for service discovery

use serde::{Deserialize, Serialize};

/// Service discovery mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum DiscoveryMode {
    /// No service discovery - use service URL directly
    #[default]
    None,

    /// Kubernetes service discovery - resolve to pod IPs
    Kubernetes,

    /// Tailscale mesh networking discovery - resolve via MagicDNS
    Tailscale(TailscaleConfig),
}

/// Tailscale-specific discovery configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleConfig {
    /// Local cluster name (e.g., "us-west-1")
    pub local_cluster: String,

    /// Remote clusters to discover
    #[serde(default)]
    pub remote_clusters: Vec<RemoteClusterConfigEntry>,
}

/// Configuration for a remote cluster in Tailscale mesh
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteClusterConfigEntry {
    /// Cluster name (e.g., "eu-west-1")
    pub name: String,

    /// Tailscale domain for this cluster (e.g., "eu-west-1.ts.net")
    pub tailscale_domain: String,

    /// Service name within the cluster (e.g., "inferadb-engine")
    pub service_name: String,

    /// Service port
    pub port: u16,

    /// Region ID for replication topology mapping (defaults to cluster name)
    #[serde(default)]
    pub region_id: Option<String>,
}

impl RemoteClusterConfigEntry {
    /// Get the region ID, defaulting to the cluster name
    pub fn region_id(&self) -> &str {
        self.region_id.as_deref().unwrap_or(&self.name)
    }
}

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL for discovered endpoints (in seconds)
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,

    /// Health check interval (in seconds)
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::None,
            cache_ttl: default_cache_ttl(),
            health_check_interval: default_health_check_interval(),
        }
    }
}

fn default_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_health_check_interval() -> u64 {
    30 // 30 seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_mode_default() {
        let mode: DiscoveryMode = Default::default();
        assert_eq!(mode, DiscoveryMode::None);
    }

    #[test]
    fn test_discovery_config_default() {
        let config: DiscoveryConfig = Default::default();
        assert_eq!(config.mode, DiscoveryMode::None);
        assert_eq!(config.cache_ttl, 300);
        assert_eq!(config.health_check_interval, 30);
    }

    #[test]
    fn test_discovery_mode_serialization() {
        // Tagged enum serializes with "type" field
        let mode = DiscoveryMode::Kubernetes;
        let json = serde_json::to_string(&mode).unwrap();
        assert!(json.contains("\"type\":\"kubernetes\""));

        let mode = DiscoveryMode::None;
        let json = serde_json::to_string(&mode).unwrap();
        assert!(json.contains("\"type\":\"none\""));
    }

    #[test]
    fn test_discovery_config_serialization() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Kubernetes,
            cache_ttl: 600,
            health_check_interval: 60,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("kubernetes"));
        assert!(yaml.contains("cache_ttl: 600"));
        assert!(yaml.contains("health_check_interval: 60"));
    }

    #[test]
    fn test_tailscale_config_serialization() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Tailscale(TailscaleConfig {
                local_cluster: "us-west-1".to_string(),
                remote_clusters: vec![RemoteClusterConfigEntry {
                    name: "eu-central-1".to_string(),
                    tailscale_domain: "eu-central-1.ts.net".to_string(),
                    service_name: "inferadb-engine".to_string(),
                    port: 8080,
                    region_id: None,
                }],
            }),
            cache_ttl: 300,
            health_check_interval: 30,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("tailscale"));
        assert!(yaml.contains("us-west-1"));
        assert!(yaml.contains("eu-central-1.ts.net"));
    }

    #[test]
    fn test_tailscale_config_deserialization() {
        let yaml = r#"
mode:
  type: tailscale
  local_cluster: us-west-1
  remote_clusters:
    - name: eu-central-1
      tailscale_domain: eu-central-1.ts.net
      service_name: inferadb-engine
      port: 8080
      region_id: eu-central
cache_ttl: 600
health_check_interval: 60
"#;
        let config: DiscoveryConfig = serde_yaml::from_str(yaml).unwrap();

        match config.mode {
            DiscoveryMode::Tailscale(ts_config) => {
                assert_eq!(ts_config.local_cluster, "us-west-1");
                assert_eq!(ts_config.remote_clusters.len(), 1);
                assert_eq!(ts_config.remote_clusters[0].name, "eu-central-1");
                assert_eq!(ts_config.remote_clusters[0].region_id(), "eu-central");
            },
            _ => panic!("Expected Tailscale mode"),
        }
        assert_eq!(config.cache_ttl, 600);
    }

    #[test]
    fn test_remote_cluster_region_id_default() {
        let entry = RemoteClusterConfigEntry {
            name: "eu-central-1".to_string(),
            tailscale_domain: "eu-central-1.ts.net".to_string(),
            service_name: "inferadb-engine".to_string(),
            port: 8080,
            region_id: None,
        };

        // Should default to cluster name
        assert_eq!(entry.region_id(), "eu-central-1");

        let entry_with_region = RemoteClusterConfigEntry {
            name: "eu-central-1".to_string(),
            tailscale_domain: "eu-central-1.ts.net".to_string(),
            service_name: "inferadb-engine".to_string(),
            port: 8080,
            region_id: Some("eu-central".to_string()),
        };

        // Should use explicit region ID
        assert_eq!(entry_with_region.region_id(), "eu-central");
    }
}
