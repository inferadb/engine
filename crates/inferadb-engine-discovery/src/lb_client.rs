//! Load balancing client with health tracking and circuit breaker
//!
//! Provides client-side load balancing across discovered endpoints with:
//! - Round-robin distribution
//! - Circuit breaker pattern (open after 5 failures, reopen after 30s)
//! - Health tracking per endpoint
//! - Automatic retry across endpoints (max 3 retries)
//! - Thread-safe endpoint state management

use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use tracing::{debug, error, warn};

use crate::{
    Endpoint,
    error::{DiscoveryError, Result},
    metrics::{record_failover, record_lb_request, set_endpoint_health},
};

/// Load balancing client with health-aware routing
pub struct LoadBalancingClient {
    /// Shared endpoint state across threads
    endpoints: Arc<RwLock<Vec<EndpointState>>>,
    /// Current index for round-robin selection
    current_index: Arc<RwLock<usize>>,
}

/// State tracking for an individual endpoint
struct EndpointState {
    /// The endpoint information
    endpoint: Endpoint,
    /// Number of consecutive failures
    failures: u32,
    /// Timestamp of last failure
    last_failure: Option<Instant>,
    /// Circuit breaker state
    circuit_breaker: CircuitState,
}

/// Circuit breaker states for an endpoint
enum CircuitState {
    /// Normal operation - endpoint is healthy
    Closed,
    /// Too many failures - not routing traffic
    Open { since: Instant },
}

impl LoadBalancingClient {
    /// Create a new load balancing client with initial endpoints
    pub fn new(endpoints: Vec<Endpoint>) -> Self {
        let endpoint_states: Vec<EndpointState> = endpoints
            .into_iter()
            .map(|e| {
                // Initialize metrics for this endpoint
                set_endpoint_health(&e.url, true);

                EndpointState {
                    endpoint: e,
                    failures: 0,
                    last_failure: None,
                    circuit_breaker: CircuitState::Closed,
                }
            })
            .collect();

        debug!(count = endpoint_states.len(), "Initialized load balancing client");

        Self {
            endpoints: Arc::new(RwLock::new(endpoint_states)),
            current_index: Arc::new(RwLock::new(0)),
        }
    }

    /// Get the next healthy endpoint URL
    ///
    /// Uses round-robin selection, skipping endpoints with open circuit breakers.
    /// If all endpoints are unhealthy, returns the first endpoint anyway (circuit may recover).
    pub fn get_next_healthy_endpoint(&self) -> Result<String> {
        let endpoints = self
            .endpoints
            .read()
            .map_err(|e| DiscoveryError::other(format!("Failed to read endpoints: {}", e)))?;

        let total = endpoints.len();

        if total == 0 {
            return Err(DiscoveryError::other("No endpoints available"));
        }

        // Try to find healthy endpoint (round-robin)
        let start_index = *self
            .current_index
            .read()
            .map_err(|e| DiscoveryError::other(format!("Failed to read index: {}", e)))?;

        for offset in 0..total {
            let index = (start_index + offset) % total;
            let endpoint_state = &endpoints[index];

            if is_healthy(&endpoint_state.circuit_breaker) {
                // Update current index for next call
                let mut current_idx = self
                    .current_index
                    .write()
                    .map_err(|e| DiscoveryError::other(format!("Failed to write index: {}", e)))?;
                *current_idx = (index + 1) % total;

                debug!(
                    endpoint = %endpoint_state.endpoint.url,
                    index = index,
                    "Selected healthy endpoint"
                );

                return Ok(endpoint_state.endpoint.url.clone());
            }
        }

        // All endpoints unhealthy, return first anyway (circuit may recover)
        warn!("All endpoints unhealthy, returning first endpoint");
        Ok(endpoints[0].endpoint.url.clone())
    }

    /// Mark the current endpoint as successful
    ///
    /// Resets failure count and closes circuit breaker.
    pub fn mark_success(&self, endpoint_url: &str) {
        let mut endpoints = match self.endpoints.write() {
            Ok(eps) => eps,
            Err(e) => {
                error!(error = %e, "Failed to write endpoints for success");
                return;
            },
        };

        if let Some(endpoint_state) = endpoints.iter_mut().find(|e| e.endpoint.url == endpoint_url)
        {
            endpoint_state.failures = 0;
            endpoint_state.circuit_breaker = CircuitState::Closed;

            // Update metrics
            record_lb_request(&endpoint_state.endpoint.url, "success");
            set_endpoint_health(&endpoint_state.endpoint.url, true);

            debug!(endpoint = %endpoint_url, "Marked endpoint as successful");
        }
    }

    /// Mark the current endpoint as failed
    ///
    /// Increments failure count and opens circuit breaker after 5 failures.
    pub fn mark_failure(&self, endpoint_url: &str) {
        let mut endpoints = match self.endpoints.write() {
            Ok(eps) => eps,
            Err(e) => {
                error!(error = %e, "Failed to write endpoints for failure");
                return;
            },
        };

        if let Some(endpoint_state) = endpoints.iter_mut().find(|e| e.endpoint.url == endpoint_url)
        {
            endpoint_state.failures += 1;
            endpoint_state.last_failure = Some(Instant::now());

            // Update metrics
            record_lb_request(&endpoint_state.endpoint.url, "error");

            // Open circuit after 5 failures
            if endpoint_state.failures >= 5 {
                endpoint_state.circuit_breaker = CircuitState::Open { since: Instant::now() };
                set_endpoint_health(&endpoint_state.endpoint.url, false);

                warn!(
                    endpoint = %endpoint_state.endpoint.url,
                    failures = endpoint_state.failures,
                    "Circuit breaker opened for endpoint"
                );
            } else {
                debug!(
                    endpoint = %endpoint_state.endpoint.url,
                    failures = endpoint_state.failures,
                    "Marked endpoint as failed"
                );
            }
        }
    }

    /// Attempt a request with automatic failover
    ///
    /// Tries up to 3 endpoints, selecting the next healthy endpoint on each failure.
    /// Records metrics for each attempt and failover events.
    pub fn try_request_with_failover<F, T>(&self, mut request_fn: F) -> Result<T>
    where
        F: FnMut(&str) -> Result<T>,
    {
        let max_retries = 3;
        let mut last_error = None;
        let mut previous_endpoint: Option<String> = None;

        for attempt in 0..max_retries {
            let endpoint_url = self.get_next_healthy_endpoint()?;

            // Record failover if we switched endpoints
            if let Some(prev) = previous_endpoint.as_ref()
                && prev != &endpoint_url
            {
                record_failover(prev, &endpoint_url);
                debug!(from = %prev, to = %endpoint_url, "Failover to next endpoint");
            }

            match request_fn(&endpoint_url) {
                Ok(response) => {
                    self.mark_success(&endpoint_url);
                    return Ok(response);
                },
                Err(e) => {
                    warn!(
                        attempt = attempt + 1,
                        max_retries = max_retries,
                        endpoint = %endpoint_url,
                        error = %e,
                        "Request failed, will retry with next endpoint"
                    );
                    self.mark_failure(&endpoint_url);
                    last_error = Some(e);
                    previous_endpoint = Some(endpoint_url);
                },
            }
        }

        Err(last_error.unwrap_or_else(|| DiscoveryError::other("All retries failed")))
    }

    /// Update endpoints from discovery refresh
    ///
    /// Replaces the current endpoint list with newly discovered endpoints.
    /// All endpoints are initialized with healthy state.
    pub fn update_endpoints(&self, new_endpoints: Vec<Endpoint>) {
        let mut endpoints = match self.endpoints.write() {
            Ok(eps) => eps,
            Err(e) => {
                error!(error = %e, "Failed to write endpoints for update");
                return;
            },
        };

        *endpoints = new_endpoints
            .into_iter()
            .map(|e| {
                // Initialize metrics for new endpoints
                set_endpoint_health(&e.url, true);

                EndpointState {
                    endpoint: e,
                    failures: 0,
                    last_failure: None,
                    circuit_breaker: CircuitState::Closed,
                }
            })
            .collect();

        debug!(count = endpoints.len(), "Updated endpoint list");
    }

    /// Get the current list of endpoints (for diagnostics)
    pub fn get_endpoints(&self) -> Vec<String> {
        match self.endpoints.read() {
            Ok(eps) => eps.iter().map(|e| e.endpoint.url.clone()).collect(),
            Err(e) => {
                error!(error = %e, "Failed to read endpoints");
                vec![]
            },
        }
    }
}

/// Check if an endpoint's circuit breaker allows traffic
///
/// Returns true if:
/// - Circuit is closed (normal operation)
/// - Circuit has been open for >30 seconds (auto-recovery)
fn is_healthy(circuit: &CircuitState) -> bool {
    match circuit {
        CircuitState::Closed => true,
        CircuitState::Open { since } => {
            // Reopen after 30 seconds
            let elapsed = since.elapsed();
            let should_reopen = elapsed > Duration::from_secs(30);

            if should_reopen {
                debug!(elapsed_secs = elapsed.as_secs(), "Circuit breaker reopening");
            }

            should_reopen
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client() {
        let endpoints = vec![
            Endpoint::healthy("http://10.0.1.2:3000".to_string()),
            Endpoint::healthy("http://10.0.1.3:3000".to_string()),
        ];

        let client = LoadBalancingClient::new(endpoints);
        let urls = client.get_endpoints();

        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"http://10.0.1.2:3000".to_string()));
        assert!(urls.contains(&"http://10.0.1.3:3000".to_string()));
    }

    #[test]
    fn test_round_robin() {
        let endpoints = vec![
            Endpoint::healthy("http://10.0.1.2:3000".to_string()),
            Endpoint::healthy("http://10.0.1.3:3000".to_string()),
        ];

        let client = LoadBalancingClient::new(endpoints);

        let ep1 = client.get_next_healthy_endpoint().unwrap();
        let ep2 = client.get_next_healthy_endpoint().unwrap();
        let ep3 = client.get_next_healthy_endpoint().unwrap();

        assert_ne!(ep1, ep2);
        assert_eq!(ep1, ep3); // Should wrap around
    }

    #[test]
    fn test_mark_failure_opens_circuit() {
        let endpoints = vec![Endpoint::healthy("http://10.0.1.2:3000".to_string())];

        let client = LoadBalancingClient::new(endpoints);
        let endpoint_url = "http://10.0.1.2:3000";

        // Mark 5 failures to open circuit
        for _ in 0..5 {
            client.mark_failure(endpoint_url);
        }

        // Check that endpoint is marked unhealthy
        let eps = client.endpoints.read().unwrap();
        assert!(matches!(eps[0].circuit_breaker, CircuitState::Open { .. }));
        assert_eq!(eps[0].failures, 5);
    }

    #[test]
    fn test_mark_success_resets_failures() {
        let endpoints = vec![Endpoint::healthy("http://10.0.1.2:3000".to_string())];

        let client = LoadBalancingClient::new(endpoints);
        let endpoint_url = "http://10.0.1.2:3000";

        // Mark some failures
        client.mark_failure(endpoint_url);
        client.mark_failure(endpoint_url);

        // Mark success should reset
        client.mark_success(endpoint_url);

        let eps = client.endpoints.read().unwrap();
        assert_eq!(eps[0].failures, 0);
        assert!(matches!(eps[0].circuit_breaker, CircuitState::Closed));
    }

    #[test]
    fn test_update_endpoints() {
        let initial = vec![Endpoint::healthy("http://10.0.1.2:3000".to_string())];

        let client = LoadBalancingClient::new(initial);

        let new_endpoints = vec![
            Endpoint::healthy("http://10.0.1.3:3000".to_string()),
            Endpoint::healthy("http://10.0.1.4:3000".to_string()),
        ];

        client.update_endpoints(new_endpoints);

        let urls = client.get_endpoints();
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"http://10.0.1.3:3000".to_string()));
        assert!(urls.contains(&"http://10.0.1.4:3000".to_string()));
    }

    #[test]
    fn test_no_endpoints_error() {
        let client = LoadBalancingClient::new(vec![]);
        let result = client.get_next_healthy_endpoint();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No endpoints"));
    }

    #[test]
    fn test_is_healthy_closed() {
        assert!(is_healthy(&CircuitState::Closed));
    }

    #[test]
    fn test_is_healthy_open_recent() {
        let circuit = CircuitState::Open { since: Instant::now() };
        assert!(!is_healthy(&circuit));
    }

    #[test]
    fn test_is_healthy_open_old() {
        let circuit = CircuitState::Open { since: Instant::now() - Duration::from_secs(31) };
        assert!(is_healthy(&circuit));
    }
}
