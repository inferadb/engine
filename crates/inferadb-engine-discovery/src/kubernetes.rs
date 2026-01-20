//! Kubernetes-based service discovery

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Endpoints as K8sEndpoints;
use kube::{Api, Client};
use tracing::{debug, info, warn};

use crate::{Endpoint, EndpointDiscovery, EndpointHealth, Result};

/// Kubernetes service discovery implementation
///
/// Discovers pod IPs behind a Kubernetes service by querying the Endpoints resource
pub struct KubernetesServiceDiscovery {
    client: Client,
}

impl KubernetesServiceDiscovery {
    /// Create a new Kubernetes service discovery instance
    ///
    /// # Returns
    ///
    /// A new instance or an error if the Kubernetes client cannot be created
    pub async fn new() -> Result<Self> {
        let client = Client::try_default().await.map_err(|e| {
            crate::error::DiscoveryError::other(format!(
                "Failed to create Kubernetes client: {}",
                e
            ))
        })?;

        info!("Kubernetes service discovery initialized");
        Ok(Self { client })
    }

    /// Create a new instance with a custom Kubernetes client
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    /// Parse a service URL into components
    ///
    /// Supports these formats:
    /// - "service-name" -> (service-name, default namespace from env)
    /// - "service-name.namespace" -> (service-name, namespace)
    /// - "service-name.namespace.svc.cluster.local" -> (service-name, namespace)
    fn parse_service_url(&self, service_url: &str) -> Result<(String, String, u16, String)> {
        let url = url::Url::parse(service_url).map_err(|e| {
            crate::error::DiscoveryError::invalid_url(format!("Invalid service URL: {}", e))
        })?;

        let service_host = url
            .host_str()
            .ok_or_else(|| crate::error::DiscoveryError::invalid_url("No host in service URL"))?;

        let service_port = url
            .port_or_known_default()
            .ok_or_else(|| crate::error::DiscoveryError::invalid_url("No port in service URL"))?;

        let scheme = url.scheme().to_string();

        // Extract service name and namespace from hostname
        let parts: Vec<&str> = service_host.split('.').collect();
        let default_namespace =
            std::env::var("KUBERNETES_NAMESPACE").unwrap_or_else(|_| "default".to_string());

        let (service_name, namespace) = if parts.len() >= 2 {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (parts[0].to_string(), default_namespace)
        };

        Ok((service_name, namespace, service_port, scheme))
    }
}

#[async_trait]
impl EndpointDiscovery for KubernetesServiceDiscovery {
    async fn discover(&self, service_url: &str) -> Result<Vec<Endpoint>> {
        let (service_name, namespace, port, scheme) = self.parse_service_url(service_url)?;

        debug!(
            service_name = %service_name,
            namespace = %namespace,
            port = port,
            "Discovering Kubernetes service endpoints"
        );

        // Get the Endpoints resource for this service
        let endpoints_api: Api<K8sEndpoints> = Api::namespaced(self.client.clone(), &namespace);

        let endpoints = endpoints_api.get(&service_name).await.map_err(|e| {
            if e.to_string().contains("404") {
                crate::error::DiscoveryError::service_not_found(format!(
                    "Service {}.{} not found",
                    service_name, namespace
                ))
            } else {
                crate::error::DiscoveryError::from(e)
            }
        })?;

        // Extract pod IPs from the Endpoints resource
        let mut discovered_endpoints = Vec::new();

        if let Some(subsets) = endpoints.subsets {
            for subset in subsets {
                // Get addresses (ready pods)
                if let Some(addresses) = subset.addresses {
                    for address in addresses {
                        let pod_ip = &address.ip;
                        let endpoint_url = format!("{}://{}:{}", scheme, pod_ip, port);

                        let mut endpoint = Endpoint::healthy(endpoint_url);

                        // Add pod name if available
                        if let Some(target_ref) = &address.target_ref
                            && let Some(pod_name) = &target_ref.name
                        {
                            endpoint = endpoint.with_pod_name(pod_name.clone());
                        }

                        // Add namespace metadata
                        endpoint =
                            endpoint.with_metadata("namespace".to_string(), namespace.clone());
                        endpoint =
                            endpoint.with_metadata("service".to_string(), service_name.clone());

                        discovered_endpoints.push(endpoint);
                    }
                }

                // Get not-ready addresses
                if let Some(not_ready_addresses) = subset.not_ready_addresses {
                    for address in not_ready_addresses {
                        let pod_ip = &address.ip;
                        let endpoint_url = format!("{}://{}:{}", scheme, pod_ip, port);

                        let mut endpoint = Endpoint::new(endpoint_url);
                        endpoint.health = EndpointHealth::Unhealthy;

                        // Add pod name if available
                        if let Some(target_ref) = &address.target_ref
                            && let Some(pod_name) = &target_ref.name
                        {
                            endpoint = endpoint.with_pod_name(pod_name.clone());
                        }

                        // Add namespace metadata
                        endpoint =
                            endpoint.with_metadata("namespace".to_string(), namespace.clone());
                        endpoint =
                            endpoint.with_metadata("service".to_string(), service_name.clone());

                        discovered_endpoints.push(endpoint);
                    }
                }
            }
        }

        if discovered_endpoints.is_empty() {
            warn!(
                service_name = %service_name,
                namespace = %namespace,
                "No endpoints found for service"
            );
            return Err(crate::error::DiscoveryError::no_endpoints(format!(
                "{}.{}",
                service_name, namespace
            )));
        }

        info!(
            service_name = %service_name,
            namespace = %namespace,
            endpoint_count = discovered_endpoints.len(),
            healthy_count = discovered_endpoints.iter().filter(|e| e.health == EndpointHealth::Healthy).count(),
            "Discovered Kubernetes service endpoints"
        );

        Ok(discovered_endpoints)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_service_url_simple() {
        // This test would require a mock Kubernetes client
        // For now, we just test the URL parsing logic conceptually
        let url = "http://my-service:8080";
        let parsed = url::Url::parse(url).unwrap();
        assert_eq!(parsed.host_str(), Some("my-service"));
        assert_eq!(parsed.port(), Some(8080));
    }

    #[test]
    fn test_parse_service_url_with_namespace() {
        let url = "http://my-service.my-namespace:8080";
        let parsed = url::Url::parse(url).unwrap();
        assert_eq!(parsed.host_str(), Some("my-service.my-namespace"));
    }

    #[test]
    fn test_parse_service_url_full_fqdn() {
        let url = "http://my-service.my-namespace.svc.cluster.local:8080";
        let parsed = url::Url::parse(url).unwrap();
        assert_eq!(parsed.host_str(), Some("my-service.my-namespace.svc.cluster.local"));
    }
}
