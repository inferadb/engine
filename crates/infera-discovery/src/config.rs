//! Configuration for service discovery

use serde::{Deserialize, Serialize};

/// Service discovery mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    /// No service discovery - use service URL directly
    #[default]
    None,

    /// Kubernetes service discovery - resolve to pod IPs
    Kubernetes,
}

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Discovery mode
    #[serde(default)]
    pub mode: DiscoveryMode,

    /// Cache TTL for discovered endpoints (in seconds)
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,

    /// Whether to enable health checking of endpoints
    #[serde(default = "default_health_check")]
    pub enable_health_check: bool,

    /// Health check interval (in seconds)
    #[serde(default = "default_health_check_interval")]
    pub health_check_interval_seconds: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::None,
            cache_ttl_seconds: default_cache_ttl(),
            enable_health_check: default_health_check(),
            health_check_interval_seconds: default_health_check_interval(),
        }
    }
}

fn default_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_health_check() -> bool {
    false
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
        assert_eq!(config.cache_ttl_seconds, 300);
        assert!(!config.enable_health_check);
        assert_eq!(config.health_check_interval_seconds, 30);
    }

    #[test]
    fn test_discovery_mode_serialization() {
        let mode = DiscoveryMode::Kubernetes;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"kubernetes\"");

        let mode = DiscoveryMode::None;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"none\"");
    }

    #[test]
    fn test_discovery_config_serialization() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Kubernetes,
            cache_ttl_seconds: 600,
            enable_health_check: true,
            health_check_interval_seconds: 60,
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(yaml.contains("kubernetes"));
        assert!(yaml.contains("cache_ttl_seconds: 600"));
        assert!(yaml.contains("enable_health_check: true"));
    }
}
