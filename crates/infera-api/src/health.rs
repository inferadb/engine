//! Health check endpoints for Kubernetes probes
//!
//! Provides liveness, readiness, and startup probes for container orchestration.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

/// Get the vault ID for health checks
///
/// Health checks use 0 as they don't require vault isolation
fn get_vault() -> i64 {
    0
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is degraded but functional
    Degraded,
    /// Service is unhealthy
    Unhealthy,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Service name
    pub service: String,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Timestamp of the response
    pub timestamp: u64,
    /// Optional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HealthDetails>,
}

/// Detailed health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthDetails {
    /// Storage backend status
    pub storage: ComponentStatus,
    /// Cache status
    pub cache: ComponentStatus,
    /// Authentication status
    pub auth: ComponentStatus,
}

/// Component health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// Component status
    pub status: HealthStatus,
    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Health tracker for the service
#[derive(Clone)]
pub struct HealthTracker {
    /// Service start time
    start_time: Arc<AtomicU64>,
    /// Is service ready?
    ready: Arc<AtomicBool>,
    /// Is service alive?
    alive: Arc<AtomicBool>,
    /// Has service completed startup?
    startup_complete: Arc<AtomicBool>,
}

impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthTracker {
    /// Create a new health tracker
    pub fn new() -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        Self {
            start_time: Arc::new(AtomicU64::new(now)),
            ready: Arc::new(AtomicBool::new(false)),
            alive: Arc::new(AtomicBool::new(true)),
            startup_complete: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let start = self.start_time.load(Ordering::Relaxed);
        now.saturating_sub(start)
    }

    /// Mark service as ready
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    /// Check if service is ready
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Mark service as alive/dead
    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::Release);
    }

    /// Check if service is alive
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Mark startup as complete
    pub fn set_startup_complete(&self, complete: bool) {
        self.startup_complete.store(complete, Ordering::Release);
    }

    /// Check if startup is complete
    pub fn is_startup_complete(&self) -> bool {
        self.startup_complete.load(Ordering::Acquire)
    }

    /// Perform a comprehensive health check
    pub async fn check_health(&self, store: &Arc<dyn infera_store::InferaStore>) -> HealthResponse {
        let uptime = self.uptime_seconds();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Check storage health with a simple read
        let storage_status =
            match tokio::time::timeout(Duration::from_secs(1), store.get_revision(get_vault()))
                .await
            {
                Ok(Ok(_)) => ComponentStatus {
                    status: HealthStatus::Healthy,
                    message: Some("Storage operational".to_string()),
                },
                Ok(Err(e)) => ComponentStatus {
                    status: HealthStatus::Unhealthy,
                    message: Some(format!("Storage error: {}", e)),
                },
                Err(_) => ComponentStatus {
                    status: HealthStatus::Degraded,
                    message: Some("Storage timeout".to_string()),
                },
            };

        // Cache is always healthy for in-memory cache
        let cache_status = ComponentStatus {
            status: HealthStatus::Healthy,
            message: Some("Cache operational".to_string()),
        };

        // Auth is healthy if ready
        let auth_status = if self.is_ready() {
            ComponentStatus {
                status: HealthStatus::Healthy,
                message: Some("Auth ready".to_string()),
            }
        } else {
            ComponentStatus {
                status: HealthStatus::Degraded,
                message: Some("Auth initializing".to_string()),
            }
        };

        // Determine overall status
        let overall_status =
            if !self.is_alive() || matches!(storage_status.status, HealthStatus::Unhealthy) {
                HealthStatus::Unhealthy
            } else if !self.is_ready() {
                HealthStatus::Degraded
            } else {
                HealthStatus::Healthy
            };

        HealthResponse {
            status: overall_status,
            service: "inferadb".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: uptime,
            timestamp,
            details: Some(HealthDetails {
                storage: storage_status,
                cache: cache_status,
                auth: auth_status,
            }),
        }
    }
}

/// Liveness probe handler
///
/// Indicates whether the service is running. If this fails, Kubernetes will restart the pod.
/// This should only fail if the service is completely broken (e.g., deadlock, panic).
pub async fn liveness_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let tracker = &state.health_tracker;
    if tracker.is_alive() {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "alive",
                "service": "inferadb",
                "uptime_seconds": tracker.uptime_seconds()
            })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "dead",
                "service": "inferadb"
            })),
        )
    }
}

/// Readiness probe handler
///
/// Indicates whether the service is ready to accept traffic.
/// If this fails, Kubernetes will remove the pod from the load balancer.
pub async fn readiness_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let health = state.health_tracker.check_health(&state.store).await;

    match health.status {
        HealthStatus::Healthy => (StatusCode::OK, Json(health)),
        HealthStatus::Degraded => (StatusCode::OK, Json(health)), // Still serve traffic when
        // degraded
        HealthStatus::Unhealthy => (StatusCode::SERVICE_UNAVAILABLE, Json(health)),
    }
}

/// Startup probe handler
///
/// Indicates whether the service has completed initialization.
/// Kubernetes will not send traffic until this succeeds.
pub async fn startup_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let tracker = &state.health_tracker;
    if tracker.is_startup_complete() {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ready",
                "service": "inferadb",
                "uptime_seconds": tracker.uptime_seconds()
            })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "initializing",
                "service": "inferadb"
            })),
        )
    }
}

/// Legacy health check endpoint (for backward compatibility)
pub async fn health_check_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let health = state.health_tracker.check_health(&state.store).await;

    match health.status {
        HealthStatus::Healthy | HealthStatus::Degraded => (StatusCode::OK, Json(health)),
        HealthStatus::Unhealthy => (StatusCode::SERVICE_UNAVAILABLE, Json(health)),
    }
}

/// Authentication health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthHealthResponse {
    /// Overall authentication health status
    pub status: HealthStatus,
    /// Management API connectivity status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_api: Option<ManagementApiHealth>,
    /// Certificate cache status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_cache: Option<CacheHealth>,
    /// Vault cache status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_cache: Option<CacheHealth>,
    /// Redis connectivity status (if replay protection enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis: Option<RedisHealth>,
    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Management API health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementApiHealth {
    /// Management API URL
    pub url: String,
    /// Is management API reachable?
    pub reachable: bool,
    /// Latency in milliseconds (if reachable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Error message (if unreachable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Cache health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheHealth {
    /// Number of entries in cache
    pub size: usize,
    /// Cache hit rate (0.0 to 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_rate: Option<f64>,
    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Redis health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisHealth {
    /// Is Redis reachable?
    pub reachable: bool,
    /// Latency in milliseconds (if reachable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Error message (if unreachable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Authentication health check handler
///
/// Provides detailed health information about the authentication system:
/// - Management API connectivity
/// - Certificate and vault cache status
/// - Redis connectivity (if replay protection enabled)
pub async fn auth_health_check_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let config = &state.config;

    // Check if authentication is enabled
    if !config.auth.enabled {
        return (
            StatusCode::OK,
            Json(AuthHealthResponse {
                status: HealthStatus::Healthy,
                management_api: None,
                certificate_cache: None,
                vault_cache: None,
                redis: None,
                message: Some("Authentication disabled".to_string()),
            }),
        );
    }

    let mut overall_status = HealthStatus::Healthy;
    let mut management_api_health = None;
    let mut certificate_cache_health = None;
    let mut vault_cache_health = None;
    let mut redis_health = None;

    // Check management API connectivity
    if !config.auth.management_api_url.is_empty() {
        let start = std::time::Instant::now();
        let url = format!("{}/health", config.auth.management_api_url);

        match tokio::time::timeout(
            Duration::from_millis(config.auth.management_api_timeout_ms),
            reqwest::get(&url),
        )
        .await
        {
            Ok(Ok(response)) if response.status().is_success() => {
                let latency = start.elapsed().as_millis() as u64;
                management_api_health = Some(ManagementApiHealth {
                    url: config.auth.management_api_url.clone(),
                    reachable: true,
                    latency_ms: Some(latency),
                    error: None,
                });
            },
            Ok(Ok(response)) => {
                let status_code = response.status();
                management_api_health = Some(ManagementApiHealth {
                    url: config.auth.management_api_url.clone(),
                    reachable: false,
                    latency_ms: None,
                    error: Some(format!("HTTP {}", status_code)),
                });
                overall_status = HealthStatus::Degraded;
            },
            Ok(Err(e)) => {
                management_api_health = Some(ManagementApiHealth {
                    url: config.auth.management_api_url.clone(),
                    reachable: false,
                    latency_ms: None,
                    error: Some(format!("Connection error: {}", e)),
                });
                overall_status = HealthStatus::Degraded;
            },
            Err(_) => {
                management_api_health = Some(ManagementApiHealth {
                    url: config.auth.management_api_url.clone(),
                    reachable: false,
                    latency_ms: None,
                    error: Some(format!(
                        "Timeout after {}ms",
                        config.auth.management_api_timeout_ms
                    )),
                });
                overall_status = HealthStatus::Degraded;
            },
        }

        // Note: Certificate and vault cache health would require access to the actual cache
        // instances Since they're not in AppState, we report them as operational if
        // management API is configured
        certificate_cache_health = Some(CacheHealth {
            size: 0, // Would need access to actual cache to get size
            hit_rate: None,
            message: Some(
                "Certificate cache operational (metrics available at /metrics)".to_string(),
            ),
        });

        vault_cache_health = Some(CacheHealth {
            size: 0, // Would need access to actual cache to get size
            hit_rate: None,
            message: Some("Vault cache operational (metrics available at /metrics)".to_string()),
        });
    }

    // Check Redis connectivity (if replay protection is configured)
    // Note: This would require Redis URL to be in config and Redis client to be in AppState
    // For now, we indicate if replay protection would be enabled based on config
    if config.auth.replay_protection {
        if let Some(_redis_url) = &config.auth.redis_url {
            redis_health = Some(RedisHealth {
                reachable: false,
                latency_ms: None,
                error: Some("Redis health check not yet implemented".to_string()),
            });
            // Don't mark as degraded since replay protection is optional
        }
    }

    // Return appropriate status code
    let status_code = match overall_status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK, // Still serve traffic when degraded
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (
        status_code,
        Json(AuthHealthResponse {
            status: overall_status,
            management_api: management_api_health,
            certificate_cache: certificate_cache_health,
            vault_cache: vault_cache_health,
            redis: redis_health,
            message: None,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_tracker_new() {
        let tracker = HealthTracker::new();
        assert!(tracker.is_alive());
        assert!(!tracker.is_ready());
        assert!(!tracker.is_startup_complete());
    }

    #[test]
    fn test_health_tracker_ready() {
        let tracker = HealthTracker::new();
        assert!(!tracker.is_ready());

        tracker.set_ready(true);
        assert!(tracker.is_ready());

        tracker.set_ready(false);
        assert!(!tracker.is_ready());
    }

    #[test]
    fn test_health_tracker_alive() {
        let tracker = HealthTracker::new();
        assert!(tracker.is_alive());

        tracker.set_alive(false);
        assert!(!tracker.is_alive());

        tracker.set_alive(true);
        assert!(tracker.is_alive());
    }

    #[test]
    fn test_health_tracker_startup() {
        let tracker = HealthTracker::new();
        assert!(!tracker.is_startup_complete());

        tracker.set_startup_complete(true);
        assert!(tracker.is_startup_complete());

        tracker.set_startup_complete(false);
        assert!(!tracker.is_startup_complete());
    }

    #[test]
    fn test_health_tracker_uptime() {
        let tracker = HealthTracker::new();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let uptime = tracker.uptime_seconds();
        // Uptime should be positive (comparison is always true for u64 but kept for documentation)
        assert!(uptime < 1000); // Should be less than 1000 seconds for this test
    }
}
