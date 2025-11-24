//! Background discovery refresh task
//!
//! Provides periodic endpoint refresh by querying the discovery service
//! and updating the load balancing client with newly discovered endpoints.

use std::sync::Arc;

use tokio::time::{Duration, interval};
use tracing::{debug, error, info};

use crate::{
    EndpointDiscovery, lb_client::LoadBalancingClient, metrics::record_discovery_operation,
};

/// Background task for refreshing discovered endpoints
pub struct DiscoveryRefresher {
    /// Discovery service implementation
    discovery: Arc<dyn EndpointDiscovery>,
    /// Load balancing client to update
    lb_client: Arc<LoadBalancingClient>,
    /// How often to refresh endpoints
    refresh_interval: Duration,
    /// Service URL being discovered
    service_url: String,
}

impl DiscoveryRefresher {
    /// Create a new discovery refresher
    ///
    /// # Arguments
    ///
    /// * `discovery` - The discovery service implementation
    /// * `lb_client` - The load balancing client to update
    /// * `refresh_interval_secs` - How often to refresh endpoints (in seconds)
    /// * `service_url` - The service URL being discovered (for logging)
    pub fn new(
        discovery: Arc<dyn EndpointDiscovery>,
        lb_client: Arc<LoadBalancingClient>,
        refresh_interval_secs: u64,
        service_url: String,
    ) -> Self {
        Self {
            discovery,
            lb_client,
            refresh_interval: Duration::from_secs(refresh_interval_secs),
            service_url,
        }
    }

    /// Spawn the background refresh task
    ///
    /// This creates a tokio task that periodically queries the discovery service
    /// and updates the load balancing client with new endpoints.
    ///
    /// The task runs indefinitely until the program exits or the task is cancelled.
    pub fn spawn(self: Arc<Self>) {
        info!(
            service_url = %self.service_url,
            refresh_interval_secs = self.refresh_interval.as_secs(),
            "Spawning discovery refresh task"
        );

        tokio::spawn(async move {
            let mut timer = interval(self.refresh_interval);

            loop {
                timer.tick().await;

                debug!(
                    service_url = %self.service_url,
                    "Refreshing discovered endpoints"
                );

                match self.discovery.discover(&self.service_url).await {
                    Ok(endpoints) => {
                        info!(
                            service_url = %self.service_url,
                            count = endpoints.len(),
                            "Successfully refreshed endpoints"
                        );

                        // Update load balancing client with new endpoints
                        self.lb_client.update_endpoints(endpoints);

                        // Record successful discovery
                        record_discovery_operation("success");
                    },
                    Err(e) => {
                        error!(
                            service_url = %self.service_url,
                            error = %e,
                            "Failed to refresh endpoints"
                        );

                        // Record failed discovery
                        record_discovery_operation("error");
                    },
                }
            }
        });
    }

    /// Perform an immediate refresh (useful for testing or on-demand updates)
    ///
    /// This does not spawn a background task, but performs a single refresh operation.
    pub async fn refresh_once(&self) -> crate::Result<usize> {
        debug!(
            service_url = %self.service_url,
            "Performing one-time endpoint refresh"
        );

        let endpoints = self.discovery.discover(&self.service_url).await?;

        info!(
            service_url = %self.service_url,
            count = endpoints.len(),
            "One-time refresh completed"
        );

        let count = endpoints.len();
        self.lb_client.update_endpoints(endpoints);

        record_discovery_operation("success");

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::{Endpoint, EndpointDiscovery, Result};

    struct MockDiscovery {
        endpoints: Vec<Endpoint>,
    }

    #[async_trait]
    impl EndpointDiscovery for MockDiscovery {
        async fn discover(&self, _service_url: &str) -> Result<Vec<Endpoint>> {
            Ok(self.endpoints.clone())
        }
    }

    #[tokio::test]
    async fn test_refresh_once() {
        let mock_endpoints = vec![
            Endpoint::healthy("http://10.0.1.2:3000".to_string()),
            Endpoint::healthy("http://10.0.1.3:3000".to_string()),
        ];

        let discovery = Arc::new(MockDiscovery { endpoints: mock_endpoints.clone() });

        let lb_client = Arc::new(LoadBalancingClient::new(vec![Endpoint::healthy(
            "http://old-endpoint:3000".to_string(),
        )]));

        let refresher = DiscoveryRefresher::new(
            discovery,
            lb_client.clone(),
            30,
            "http://test-service:3000".to_string(),
        );

        let count = refresher.refresh_once().await.unwrap();

        assert_eq!(count, 2);

        // Verify load balancer was updated
        let endpoints = lb_client.get_endpoints();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.contains(&"http://10.0.1.2:3000".to_string()));
        assert!(endpoints.contains(&"http://10.0.1.3:3000".to_string()));
    }

    #[tokio::test]
    async fn test_spawn_task() {
        let mock_endpoints = vec![Endpoint::healthy("http://10.0.1.2:3000".to_string())];

        let discovery = Arc::new(MockDiscovery { endpoints: mock_endpoints });

        let lb_client = Arc::new(LoadBalancingClient::new(vec![]));

        let refresher = Arc::new(DiscoveryRefresher::new(
            discovery,
            lb_client.clone(),
            1, // 1 second for fast test
            "http://test-service:3000".to_string(),
        ));

        // Spawn the task
        refresher.spawn();

        // Wait for at least one refresh
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Verify endpoints were updated
        let endpoints = lb_client.get_endpoints();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0], "http://10.0.1.2:3000");
    }
}
