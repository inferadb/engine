//! Service discovery for distributed deployments
//!
//! Provides abstractions for discovering service endpoints in Kubernetes environments,
//! enabling direct pod-to-pod communication and bypassing service proxies for improved
//! performance and latency.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod config;
pub mod error;
pub mod kubernetes;
pub mod lb_client;
pub mod metrics;
pub mod refresh;
pub mod tailscale;

pub use config::{
    DiscoveryConfig, DiscoveryMode, RemoteClusterConfigEntry, TailscaleConfig,
};
pub use error::{DiscoveryError, Result};
pub use kubernetes::KubernetesServiceDiscovery;
pub use lb_client::LoadBalancingClient;
pub use refresh::DiscoveryRefresher;
pub use tailscale::{RemoteClusterConfig, TailscaleServiceDiscovery};

/// Represents a discovered service endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Full URL of the endpoint (e.g., "http://10.0.1.2:8080")
    pub url: String,

    /// Health status of the endpoint
    pub health: EndpointHealth,

    /// Optional pod name (for Kubernetes)
    pub pod_name: Option<String>,

    /// Optional metadata (e.g., zone, region)
    pub metadata: std::collections::HashMap<String, String>,
}

impl Endpoint {
    /// Create a new endpoint with the given URL
    pub fn new(url: String) -> Self {
        Self {
            url,
            health: EndpointHealth::Unknown,
            pod_name: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Create a new healthy endpoint
    pub fn healthy(url: String) -> Self {
        Self {
            url,
            health: EndpointHealth::Healthy,
            pod_name: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Set the pod name
    pub fn with_pod_name(mut self, name: String) -> Self {
        self.pod_name = Some(name);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.url, self.health)
    }
}

/// Health status of a discovered endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointHealth {
    /// Endpoint is healthy and ready to receive traffic
    Healthy,

    /// Endpoint is unhealthy and should not receive traffic
    Unhealthy,

    /// Health status is unknown
    Unknown,
}

/// Trait for service discovery implementations
#[async_trait]
pub trait EndpointDiscovery: Send + Sync {
    /// Discover endpoints for a service
    ///
    /// # Arguments
    ///
    /// * `service_url` - The service URL to discover endpoints for
    ///   (e.g., "http://service-name:8080" or "http://service-name.namespace.svc.cluster.local:8080")
    ///
    /// # Returns
    ///
    /// A list of discovered endpoints (pod IPs in Kubernetes)
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError` if discovery fails
    async fn discover(&self, service_url: &str) -> Result<Vec<Endpoint>>;

    /// Refresh endpoint health status
    ///
    /// This is optional and may be a no-op for some implementations
    async fn refresh_health(&self, _endpoints: &mut [Endpoint]) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_new() {
        let endpoint = Endpoint::new("http://10.0.1.2:8080".to_string());
        assert_eq!(endpoint.url, "http://10.0.1.2:8080");
        assert_eq!(endpoint.health, EndpointHealth::Unknown);
        assert!(endpoint.pod_name.is_none());
        assert!(endpoint.metadata.is_empty());
    }

    #[test]
    fn test_endpoint_healthy() {
        let endpoint = Endpoint::healthy("http://10.0.1.2:8080".to_string());
        assert_eq!(endpoint.health, EndpointHealth::Healthy);
    }

    #[test]
    fn test_endpoint_with_pod_name() {
        let endpoint =
            Endpoint::new("http://10.0.1.2:8080".to_string()).with_pod_name("my-pod-0".to_string());
        assert_eq!(endpoint.pod_name, Some("my-pod-0".to_string()));
    }

    #[test]
    fn test_endpoint_with_metadata() {
        let endpoint = Endpoint::new("http://10.0.1.2:8080".to_string())
            .with_metadata("zone".to_string(), "us-west-1a".to_string());
        assert_eq!(endpoint.metadata.get("zone"), Some(&"us-west-1a".to_string()));
    }
}
