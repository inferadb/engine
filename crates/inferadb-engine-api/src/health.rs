//! Health check endpoints for Kubernetes probes
//!
//! Provides standard Kubernetes health endpoints following the API server conventions:
//! - `/livez` - Liveness probe (is the process alive?)
//! - `/readyz` - Readiness probe (can it accept traffic?)
//! - `/startupz` - Startup probe (has initialization completed?)
//! - `/healthz` - Detailed health status for debugging/monitoring

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
    /// Get current timestamp in seconds since UNIX epoch, defaulting to 0 on error.
    #[inline]
    fn current_timestamp_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Create a new health tracker
    pub fn new() -> Self {
        let now = Self::current_timestamp_secs();

        Self {
            start_time: Arc::new(AtomicU64::new(now)),
            ready: Arc::new(AtomicBool::new(false)),
            alive: Arc::new(AtomicBool::new(true)),
            startup_complete: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        let now = Self::current_timestamp_secs();
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
    pub async fn check_health(
        &self,
        store: &Arc<dyn inferadb_engine_store::InferaStore>,
    ) -> HealthResponse {
        let uptime = self.uptime_seconds();
        let timestamp = Self::current_timestamp_secs();

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
            service: "inferadb-engine".to_string(),
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

/// Liveness probe handler (`/livez`)
///
/// Indicates whether the service is running. If this fails, Kubernetes will restart the pod.
/// This should only fail if the service is completely broken (e.g., deadlock, panic).
///
/// Returns:
/// - 200 OK if the service is alive
/// - 503 Service Unavailable if the service is dead
pub async fn livez_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let tracker = &state.health_tracker;
    if tracker.is_alive() { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }
}

/// Readiness probe handler (`/readyz`)
///
/// Indicates whether the service is ready to accept traffic.
/// If this fails, Kubernetes will remove the pod from the load balancer.
///
/// Returns:
/// - 200 OK if the service is ready (healthy or degraded)
/// - 503 Service Unavailable if the service is unhealthy
pub async fn readyz_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let health = state.health_tracker.check_health(&state.store).await;

    match health.status {
        HealthStatus::Healthy | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Startup probe handler (`/startupz`)
///
/// Indicates whether the service has completed initialization.
/// Kubernetes will not send traffic until this succeeds.
///
/// Returns:
/// - 200 OK if startup is complete
/// - 503 Service Unavailable if still initializing
pub async fn startupz_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let tracker = &state.health_tracker;
    if tracker.is_startup_complete() { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }
}

/// Detailed health check handler (`/healthz`)
///
/// Returns comprehensive health information including component status.
/// Useful for debugging and monitoring dashboards.
///
/// Returns JSON with detailed health status including:
/// - Overall status (healthy/degraded/unhealthy)
/// - Service name and version
/// - Uptime in seconds
/// - Component-level health details (storage, cache, auth)
pub async fn healthz_handler(State(state): State<crate::AppState>) -> impl IntoResponse {
    let health = state.health_tracker.check_health(&state.store).await;

    match health.status {
        HealthStatus::Healthy | HealthStatus::Degraded => (StatusCode::OK, Json(health)),
        HealthStatus::Unhealthy => (StatusCode::SERVICE_UNAVAILABLE, Json(health)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
