//! Dynamic log reconfiguration support
//!
//! Allows runtime reconfiguration of log levels and filters without restarting the service.

use anyhow::Result;
use std::sync::{Arc, RwLock};
use tracing::Level;
use tracing_subscriber::{reload, EnvFilter, Registry};

/// Handle for dynamic log reconfiguration
#[derive(Clone)]
pub struct LogReconfigHandle {
    filter_handle: Arc<RwLock<reload::Handle<EnvFilter, Registry>>>,
}

impl LogReconfigHandle {
    /// Create a new reconfiguration handle
    pub fn new(filter_handle: reload::Handle<EnvFilter, Registry>) -> Self {
        Self {
            filter_handle: Arc::new(RwLock::new(filter_handle)),
        }
    }

    /// Update the log filter
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use infera_observe::reconfigure::LogReconfigHandle;
    /// # fn example(handle: LogReconfigHandle) {
    /// // Set to debug level for all modules
    /// handle.set_filter("debug").unwrap();
    ///
    /// // Set specific module to trace level
    /// handle.set_filter("info,infera_core=trace").unwrap();
    /// # }
    /// ```
    pub fn set_filter(&self, filter: &str) -> Result<()> {
        let new_filter = EnvFilter::try_new(filter)?;

        let handle = self
            .filter_handle
            .read()
            .map_err(|e| anyhow::anyhow!("Failed to acquire read lock: {}", e))?;

        handle
            .reload(new_filter)
            .map_err(|e| anyhow::anyhow!("Failed to reload filter: {}", e))?;

        tracing::info!(filter = filter, "Log filter reconfigured");
        Ok(())
    }

    /// Set log level for all modules
    pub fn set_level(&self, level: Level) -> Result<()> {
        self.set_filter(&level.to_string().to_lowercase())
    }

    /// Set log level for a specific module
    pub fn set_module_level(&self, module: &str, level: Level) -> Result<()> {
        let filter = format!("info,{}={}", module, level.to_string().to_lowercase());
        self.set_filter(&filter)
    }

    /// Enable trace level for a specific module (useful for debugging)
    pub fn enable_module_trace(&self, module: &str) -> Result<()> {
        self.set_module_level(module, Level::TRACE)
    }

    /// Disable logging for a specific module
    pub fn disable_module(&self, module: &str) -> Result<()> {
        let filter = format!("info,{}=off", module);
        self.set_filter(&filter)
    }

    /// Get current filter as string (for display/debugging)
    pub fn current_filter(&self) -> String {
        // Note: EnvFilter doesn't expose its current state easily,
        // so we store it separately if needed
        "Current filter not directly accessible from EnvFilter".to_string()
    }
}

/// Configuration snapshot for persistence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogConfigSnapshot {
    /// Current filter directive
    pub filter: String,
    /// Timestamp of last change
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// User or system that made the change
    pub updated_by: String,
}

impl LogConfigSnapshot {
    /// Create a new snapshot
    pub fn new(filter: String, updated_by: String) -> Self {
        Self {
            filter,
            updated_at: chrono::Utc::now(),
            updated_by,
        }
    }

    /// Save snapshot to file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load snapshot from file
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let snapshot = serde_json::from_str(&json)?;
        Ok(snapshot)
    }
}

/// Manager for log reconfiguration with history tracking
pub struct LogReconfigManager {
    handle: LogReconfigHandle,
    history: Arc<RwLock<Vec<LogConfigSnapshot>>>,
    snapshot_path: Option<std::path::PathBuf>,
}

impl LogReconfigManager {
    /// Create a new manager
    pub fn new(handle: LogReconfigHandle) -> Self {
        Self {
            handle,
            history: Arc::new(RwLock::new(Vec::new())),
            snapshot_path: None,
        }
    }

    /// Enable snapshot persistence to file
    pub fn with_snapshot_path(mut self, path: std::path::PathBuf) -> Self {
        self.snapshot_path = Some(path);
        self
    }

    /// Apply a filter and record in history
    pub fn apply_filter(&self, filter: &str, updated_by: &str) -> Result<()> {
        // Apply the filter
        self.handle.set_filter(filter)?;

        // Create snapshot
        let snapshot = LogConfigSnapshot::new(filter.to_string(), updated_by.to_string());

        // Save to file if configured
        if let Some(path) = &self.snapshot_path {
            snapshot.save_to_file(path)?;
        }

        // Add to history
        let mut history = self
            .history
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire write lock: {}", e))?;
        history.push(snapshot);

        // Limit history size
        if history.len() > 100 {
            history.drain(0..50);
        }

        Ok(())
    }

    /// Get configuration history
    pub fn get_history(&self) -> Vec<LogConfigSnapshot> {
        self.history.read().map(|h| h.clone()).unwrap_or_default()
    }

    /// Restore from snapshot file
    pub fn restore_from_snapshot(&self) -> Result<()> {
        let path = self
            .snapshot_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No snapshot path configured"))?;

        let snapshot = LogConfigSnapshot::load_from_file(path)?;
        self.handle.set_filter(&snapshot.filter)?;

        tracing::info!(
            filter = %snapshot.filter,
            updated_at = %snapshot.updated_at,
            updated_by = %snapshot.updated_by,
            "Log configuration restored from snapshot"
        );

        Ok(())
    }

    /// Get the underlying handle for direct manipulation
    pub fn handle(&self) -> &LogReconfigHandle {
        &self.handle
    }
}

/// HTTP API for log reconfiguration
#[cfg(feature = "http-api")]
pub mod http_api {
    use super::*;
    use axum::{
        extract::State,
        http::StatusCode,
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    #[derive(Deserialize)]
    pub struct SetFilterRequest {
        pub filter: String,
        #[serde(default = "default_user")]
        pub updated_by: String,
    }

    fn default_user() -> String {
        "api".to_string()
    }

    #[derive(Serialize)]
    pub struct SetFilterResponse {
        pub success: bool,
        pub message: String,
    }

    #[derive(Serialize)]
    pub struct GetHistoryResponse {
        pub history: Vec<LogConfigSnapshot>,
    }

    /// Create HTTP router for log reconfiguration
    pub fn create_router(manager: Arc<LogReconfigManager>) -> Router {
        Router::new()
            .route("/logging/filter", post(set_filter))
            .route("/logging/history", get(get_history))
            .with_state(manager)
    }

    async fn set_filter(
        State(manager): State<Arc<LogReconfigManager>>,
        Json(req): Json<SetFilterRequest>,
    ) -> impl IntoResponse {
        match manager.apply_filter(&req.filter, &req.updated_by) {
            Ok(()) => (
                StatusCode::OK,
                Json(SetFilterResponse {
                    success: true,
                    message: format!("Filter updated to: {}", req.filter),
                }),
            ),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(SetFilterResponse {
                    success: false,
                    message: format!("Failed to update filter: {}", e),
                }),
            ),
        }
    }

    async fn get_history(State(manager): State<Arc<LogReconfigManager>>) -> impl IntoResponse {
        let history = manager.get_history();
        (StatusCode::OK, Json(GetHistoryResponse { history }))
    }
}

/// Initialize logging with dynamic reconfiguration support
pub fn init_with_reload(
    config: super::logging::LogConfig,
) -> Result<(LogReconfigHandle, impl tracing::Subscriber + Send + Sync)> {
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::prelude::*;

    let env_filter = if let Some(filter) = config.filter {
        EnvFilter::try_new(filter)?
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,infera=debug"))
    };

    let (filter, reload_handle) = reload::Layer::new(env_filter);

    let fmt_span = if config.log_spans {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(config.include_target)
        .with_thread_ids(config.include_thread_id)
        .with_file(config.include_location)
        .with_line_number(config.include_location)
        .with_span_events(fmt_span);

    let subscriber = Registry::default().with(filter).with(fmt_layer);

    let handle = LogReconfigHandle::new(reload_handle);

    Ok((handle, subscriber))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_snapshot() {
        let snapshot = LogConfigSnapshot::new("debug".to_string(), "test_user".to_string());

        assert_eq!(snapshot.filter, "debug");
        assert_eq!(snapshot.updated_by, "test_user");
    }

    #[test]
    fn test_snapshot_save_load() {
        let temp_dir = std::env::temp_dir();
        let snapshot_path = temp_dir.join("test_log_snapshot.json");

        let snapshot = LogConfigSnapshot::new("trace".to_string(), "test".to_string());
        snapshot.save_to_file(&snapshot_path).unwrap();

        let loaded = LogConfigSnapshot::load_from_file(&snapshot_path).unwrap();
        assert_eq!(loaded.filter, "trace");
        assert_eq!(loaded.updated_by, "test");

        // Cleanup
        std::fs::remove_file(snapshot_path).ok();
    }

    #[test]
    fn test_manager_creation() {
        // Create a dummy handle for testing
        let env_filter = EnvFilter::new("info");
        let (_filter_layer, reload_handle) = reload::Layer::new(env_filter);

        // We can't easily test the full manager without a running subscriber,
        // but we can test basic creation
        let handle = LogReconfigHandle::new(reload_handle);
        let manager = LogReconfigManager::new(handle);

        assert_eq!(manager.get_history().len(), 0);
    }

    #[test]
    fn test_manager_with_snapshot_path() {
        let env_filter = EnvFilter::new("info");
        let (_filter_layer, reload_handle) = reload::Layer::new(env_filter);

        let handle = LogReconfigHandle::new(reload_handle);
        let path = std::path::PathBuf::from("/tmp/test.json");
        let manager = LogReconfigManager::new(handle).with_snapshot_path(path.clone());

        assert_eq!(manager.snapshot_path, Some(path));
    }

    #[test]
    fn test_level_enum_values() {
        // Ensure Level values work as expected
        assert_eq!(Level::TRACE.to_string().to_lowercase(), "trace");
        assert_eq!(Level::DEBUG.to_string().to_lowercase(), "debug");
        assert_eq!(Level::INFO.to_string().to_lowercase(), "info");
        assert_eq!(Level::WARN.to_string().to_lowercase(), "warn");
        assert_eq!(Level::ERROR.to_string().to_lowercase(), "error");
    }
}
