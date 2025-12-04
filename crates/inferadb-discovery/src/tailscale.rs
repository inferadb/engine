//! Tailscale-based multi-region service discovery
//!
//! This module provides service discovery across multiple clusters connected via Tailscale mesh
//! networking. It enables cross-region communication by resolving Tailscale MagicDNS names to pod
//! IPs in remote clusters.

use async_trait::async_trait;
use tracing::{debug, error, info, warn};

use crate::{Endpoint, EndpointDiscovery, EndpointHealth, Result};

/// Remote cluster configuration
#[derive(Debug, Clone)]
pub struct RemoteClusterConfig {
    /// Cluster name (e.g., "eu-west-1")
    pub name: String,
    /// Tailscale domain for this cluster (e.g., "eu-west-1.ts.net")
    pub tailscale_domain: String,
    /// Service name within the cluster (e.g., "inferadb-server")
    pub service_name: String,
    /// Service port
    pub port: u16,
}

/// Tailscale mesh networking service discovery
///
/// Discovers endpoints across multiple Kubernetes clusters connected via Tailscale mesh.
/// Each cluster runs a Tailscale sidecar that exposes services via MagicDNS.
pub struct TailscaleServiceDiscovery {
    /// Local cluster name
    local_cluster: String,
    /// Remote clusters to discover
    remote_clusters: Vec<RemoteClusterConfig>,
}

impl TailscaleServiceDiscovery {
    /// Create a new Tailscale service discovery instance
    ///
    /// # Arguments
    ///
    /// * `local_cluster` - Name of the local cluster (e.g., "us-west-1")
    /// * `remote_clusters` - List of remote clusters to discover
    ///
    /// # Example
    ///
    /// ```rust
    /// use inferadb_discovery::tailscale::{TailscaleServiceDiscovery, RemoteClusterConfig};
    ///
    /// let remote = RemoteClusterConfig {
    ///     name: "eu-west-1".to_string(),
    ///     tailscale_domain: "eu-west-1.ts.net".to_string(),
    ///     service_name: "inferadb-server".to_string(),
    ///     port: 8080,
    /// };
    ///
    /// let discovery = TailscaleServiceDiscovery::new(
    ///     "us-west-1".to_string(),
    ///     vec![remote]
    /// );
    /// ```
    pub fn new(local_cluster: String, remote_clusters: Vec<RemoteClusterConfig>) -> Self {
        info!(
            local_cluster = %local_cluster,
            remote_cluster_count = remote_clusters.len(),
            "Initialized Tailscale service discovery"
        );

        // Record metrics
        crate::metrics::set_tailscale_clusters_total(remote_clusters.len() as i64);

        Self { local_cluster, remote_clusters }
    }

    /// Resolve a Tailscale MagicDNS name to IP addresses
    ///
    /// Uses DNS resolution to find all IPs behind a Tailscale service name.
    async fn resolve_tailscale_name(hostname: &str) -> Result<Vec<std::net::IpAddr>> {
        use tokio::net::lookup_host;

        debug!(hostname = %hostname, "Resolving Tailscale MagicDNS name");

        // Perform DNS lookup for the hostname
        let addrs: Vec<std::net::SocketAddr> = lookup_host(format!("{}:0", hostname))
            .await
            .map_err(|e| {
                crate::metrics::record_tailscale_dns_resolution(hostname, "error");
                crate::error::DiscoveryError::other(format!(
                    "Failed to resolve Tailscale hostname {}: {}",
                    hostname, e
                ))
            })?
            .collect();

        let ips: Vec<std::net::IpAddr> = addrs.iter().map(|addr| addr.ip()).collect();

        if ips.is_empty() {
            warn!(hostname = %hostname, "No IPs resolved for Tailscale hostname");
            crate::metrics::record_tailscale_dns_resolution(hostname, "no_results");
            return Err(crate::error::DiscoveryError::no_endpoints(hostname.to_string()));
        }

        debug!(
            hostname = %hostname,
            ip_count = ips.len(),
            "Resolved Tailscale MagicDNS name"
        );

        crate::metrics::record_tailscale_dns_resolution(hostname, "success");
        Ok(ips)
    }

    /// Discover endpoints for a remote cluster via Tailscale
    async fn discover_cluster_endpoints(
        &self,
        cluster: &RemoteClusterConfig,
    ) -> Result<Vec<Endpoint>> {
        let tailscale_hostname = format!("{}.{}", cluster.service_name, cluster.tailscale_domain);

        debug!(
            cluster = %cluster.name,
            hostname = %tailscale_hostname,
            "Discovering remote cluster endpoints via Tailscale"
        );

        // Resolve Tailscale MagicDNS name to IPs
        let ips = match Self::resolve_tailscale_name(&tailscale_hostname).await {
            Ok(ips) => ips,
            Err(e) => {
                warn!(
                    cluster = %cluster.name,
                    hostname = %tailscale_hostname,
                    error = %e,
                    "Failed to resolve Tailscale hostname"
                );
                return Err(e);
            },
        };

        // Build endpoints from resolved IPs
        let mut endpoints = Vec::new();
        for ip in ips {
            let endpoint_url = format!("http://{}:{}", ip, cluster.port);
            let mut endpoint = Endpoint::healthy(endpoint_url);

            // Add metadata for the cluster
            endpoint = endpoint
                .with_metadata("cluster".to_string(), cluster.name.clone())
                .with_metadata("region".to_string(), cluster.name.clone())
                .with_metadata("tailscale_domain".to_string(), cluster.tailscale_domain.clone())
                .with_metadata("discovery_method".to_string(), "tailscale".to_string());

            endpoints.push(endpoint);
        }

        info!(
            cluster = %cluster.name,
            endpoint_count = endpoints.len(),
            "Discovered Tailscale endpoints for cluster"
        );

        // Record metrics
        crate::metrics::set_tailscale_discovered_endpoints(&cluster.name, endpoints.len() as i64);

        Ok(endpoints)
    }

    /// Discover all endpoints across local and remote clusters
    async fn discover_all_clusters(&self) -> Result<Vec<Endpoint>> {
        let mut all_endpoints = Vec::new();
        let mut errors = Vec::new();

        // Discover endpoints for each remote cluster in parallel
        let mut tasks = Vec::new();

        for cluster in &self.remote_clusters {
            let cluster_clone = cluster.clone();
            let self_clone = self.clone();

            let task =
                tokio::spawn(
                    async move { self_clone.discover_cluster_endpoints(&cluster_clone).await },
                );

            tasks.push((cluster.name.clone(), task));
        }

        // Collect results
        for (cluster_name, task) in tasks {
            match task.await {
                Ok(Ok(endpoints)) => {
                    debug!(
                        cluster = %cluster_name,
                        endpoint_count = endpoints.len(),
                        "Successfully discovered cluster endpoints"
                    );
                    all_endpoints.extend(endpoints);
                },
                Ok(Err(e)) => {
                    warn!(
                        cluster = %cluster_name,
                        error = %e,
                        "Failed to discover cluster endpoints"
                    );
                    crate::metrics::record_tailscale_cluster_failure(
                        &cluster_name,
                        "discovery_error",
                    );
                    crate::metrics::set_tailscale_discovered_endpoints(&cluster_name, 0);
                    errors.push((cluster_name, e));
                },
                Err(e) => {
                    error!(
                        cluster = %cluster_name,
                        error = %e,
                        "Task failed for cluster discovery"
                    );
                    crate::metrics::record_tailscale_cluster_failure(&cluster_name, "task_failed");
                    crate::metrics::set_tailscale_discovered_endpoints(&cluster_name, 0);
                    errors.push((
                        cluster_name,
                        crate::error::DiscoveryError::other(format!("Task failed: {}", e)),
                    ));
                },
            }
        }

        // Log summary
        if !errors.is_empty() {
            warn!(
                error_count = errors.len(),
                success_count = all_endpoints.len(),
                "Some clusters failed during Tailscale discovery"
            );
        }

        if all_endpoints.is_empty() {
            return Err(crate::error::DiscoveryError::no_endpoints(format!(
                "No endpoints discovered across {} clusters",
                self.remote_clusters.len()
            )));
        }

        info!(
            total_endpoints = all_endpoints.len(),
            clusters_discovered = self.remote_clusters.len() - errors.len(),
            clusters_failed = errors.len(),
            "Completed Tailscale multi-cluster discovery"
        );

        Ok(all_endpoints)
    }
}

impl Clone for TailscaleServiceDiscovery {
    fn clone(&self) -> Self {
        Self {
            local_cluster: self.local_cluster.clone(),
            remote_clusters: self.remote_clusters.clone(),
        }
    }
}

#[async_trait]
impl EndpointDiscovery for TailscaleServiceDiscovery {
    async fn discover(&self, _service_url: &str) -> Result<Vec<Endpoint>> {
        // For Tailscale discovery, we ignore the service_url parameter
        // and discover all configured remote clusters
        debug!(
            local_cluster = %self.local_cluster,
            remote_cluster_count = self.remote_clusters.len(),
            "Starting Tailscale multi-region discovery"
        );

        self.discover_all_clusters().await
    }

    async fn refresh_health(&self, endpoints: &mut [Endpoint]) -> Result<()> {
        // Optionally implement health checking via HTTP requests
        // For now, we assume all resolved endpoints are healthy
        debug!(
            endpoint_count = endpoints.len(),
            "Refreshing health status for Tailscale endpoints"
        );

        // Mark all as healthy (DNS resolution already validates reachability)
        for endpoint in endpoints.iter_mut() {
            endpoint.health = EndpointHealth::Healthy;
        }

        Ok(())
    }
}

/// Parse a Tailscale service URL to extract components
///
/// Supports formats:
/// - "http://service.cluster.ts.net:8080"
/// - "https://service.cluster.ts.net:8443"
pub fn parse_tailscale_url(url: &str) -> Result<(String, String, u16, String)> {
    let parsed = url::Url::parse(url).map_err(|e| {
        crate::error::DiscoveryError::invalid_url(format!("Invalid Tailscale URL: {}", e))
    })?;

    let host = parsed
        .host_str()
        .ok_or_else(|| crate::error::DiscoveryError::invalid_url("No host in URL"))?;

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| crate::error::DiscoveryError::invalid_url("No port in URL"))?;

    let scheme = parsed.scheme().to_string();

    // Extract service name and Tailscale domain from hostname
    // Format: service.cluster.ts.net
    let parts: Vec<&str> = host.split('.').collect();

    if parts.len() < 3 {
        return Err(crate::error::DiscoveryError::invalid_url(format!(
            "Invalid Tailscale hostname format (expected service.cluster.ts.net): {}",
            host
        )));
    }

    let service_name = parts[0].to_string();
    let tailscale_domain = parts[1..].join(".");

    Ok((service_name, tailscale_domain, port, scheme))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tailscale_url() {
        let url = "http://inferadb-server.eu-west-1.ts.net:8080";
        let (service, domain, port, scheme) = parse_tailscale_url(url).unwrap();

        assert_eq!(service, "inferadb-server");
        assert_eq!(domain, "eu-west-1.ts.net");
        assert_eq!(port, 8080);
        assert_eq!(scheme, "http");
    }

    #[test]
    fn test_parse_tailscale_url_https() {
        let url = "https://api.cluster-1.ts.net:8443";
        let (service, domain, port, scheme) = parse_tailscale_url(url).unwrap();

        assert_eq!(service, "api");
        assert_eq!(domain, "cluster-1.ts.net");
        assert_eq!(port, 8443);
        assert_eq!(scheme, "https");
    }

    #[test]
    fn test_parse_tailscale_url_invalid() {
        let url = "http://invalid:8080";
        assert!(parse_tailscale_url(url).is_err());
    }

    #[test]
    fn test_tailscale_discovery_creation() {
        let remote = RemoteClusterConfig {
            name: "eu-west-1".to_string(),
            tailscale_domain: "eu-west-1.ts.net".to_string(),
            service_name: "inferadb-server".to_string(),
            port: 8080,
        };

        let discovery = TailscaleServiceDiscovery::new("us-west-1".to_string(), vec![remote]);

        assert_eq!(discovery.local_cluster, "us-west-1");
        assert_eq!(discovery.remote_clusters.len(), 1);
    }

    #[tokio::test]
    async fn test_discover_empty_clusters() {
        let discovery = TailscaleServiceDiscovery::new("us-west-1".to_string(), vec![]);

        let result = discovery.discover("").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_remote_cluster_config() {
        let config = RemoteClusterConfig {
            name: "ap-southeast-1".to_string(),
            tailscale_domain: "ap-southeast-1.ts.net".to_string(),
            service_name: "inferadb-management".to_string(),
            port: 3000,
        };

        assert_eq!(config.name, "ap-southeast-1");
        assert_eq!(config.port, 3000);
    }
}
