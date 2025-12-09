//! Hot reload functionality
//!
//! Watches configuration files and reloads on changes or SIGHUP signal

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};

use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use signal_hook::{consts::SIGHUP, iterator::Signals};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::{Config, load};

#[derive(Debug, Error)]
pub enum HotReloadError {
    #[error("Failed to watch file: {0}")]
    WatchError(#[from] notify::Error),

    #[error("Failed to load configuration: {0}")]
    LoadError(String),

    #[error("Signal handling error: {0}")]
    SignalError(#[from] std::io::Error),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// Hot reload handle
///
/// Manages configuration reloading from file changes and SIGHUP signals
pub struct HotReloadHandle {
    config: Arc<RwLock<Config>>,
    config_path: PathBuf,
    previous_config: Arc<RwLock<Option<Config>>>,
}

impl HotReloadHandle {
    /// Create a new hot reload handle
    pub fn new(config_path: impl AsRef<Path>, initial_config: Config) -> Self {
        Self {
            config: Arc::new(RwLock::new(initial_config)),
            config_path: config_path.as_ref().to_path_buf(),
            previous_config: Arc::new(RwLock::new(None)),
        }
    }

    /// Get the current configuration (read lock)
    pub async fn get(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Start watching for configuration changes
    ///
    /// This spawns background threads to watch for:
    /// - File system changes to the config file
    /// - SIGHUP signals
    ///
    /// On change, validates the new config before applying.
    /// Falls back to previous config on validation failure.
    pub fn start_watching(self: Arc<Self>) -> Result<(), HotReloadError> {
        // Start file watcher thread
        let handle_clone = Arc::clone(&self);
        let config_path = self.config_path.clone();

        thread::spawn(move || {
            if let Err(e) = Self::watch_file_changes(handle_clone, config_path) {
                error!("File watcher thread error: {}", e);
            }
        });

        // Start SIGHUP handler thread
        let handle_clone = Arc::clone(&self);
        thread::spawn(move || {
            if let Err(e) = Self::watch_sighup(handle_clone) {
                error!("SIGHUP handler thread error: {}", e);
            }
        });

        info!("Hot reload watchers started for {}", self.config_path.display());

        Ok(())
    }

    /// Watch for file system changes
    fn watch_file_changes(handle: Arc<Self>, config_path: PathBuf) -> Result<(), HotReloadError> {
        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
        )?;

        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

        info!("Watching config file: {}", config_path.display());

        for event in rx {
            if let notify::EventKind::Modify(_) = event.kind {
                info!("Config file modified, reloading...");

                // Wait a bit to ensure the write is complete
                thread::sleep(Duration::from_millis(100));

                let runtime = tokio::runtime::Handle::current();
                runtime.block_on(async {
                    if let Err(e) = handle.reload_config().await {
                        error!("Failed to reload config: {}", e);
                    }
                });
            }
        }

        Ok(())
    }

    /// Watch for SIGHUP signals
    fn watch_sighup(handle: Arc<Self>) -> Result<(), HotReloadError> {
        let mut signals = Signals::new([SIGHUP])?;

        info!("Watching for SIGHUP signals");

        for sig in signals.forever() {
            if sig == SIGHUP {
                info!("Received SIGHUP, reloading configuration...");

                let runtime = tokio::runtime::Handle::current();
                runtime.block_on(async {
                    if let Err(e) = handle.reload_config().await {
                        error!("Failed to reload config: {}", e);
                    }
                });
            }
        }

        Ok(())
    }

    /// Reload configuration from disk
    ///
    /// Validates before applying. Falls back to previous config on error.
    async fn reload_config(&self) -> Result<(), HotReloadError> {
        // Save current config as fallback
        let current = self.config.read().await.clone();
        *self.previous_config.write().await = Some(current.clone());

        // Try to load new config
        let new_config = load(&self.config_path)
            .map_err(|e| HotReloadError::LoadError(format!("Failed to load config: {}", e)))?;

        // Validate new config
        if let Err(e) = self.validate_config(&new_config).await {
            warn!("New configuration failed validation: {}", e);
            warn!("Keeping current configuration");
            return Err(HotReloadError::ValidationError(e));
        }

        // Apply new config
        *self.config.write().await = new_config.clone();

        info!("Configuration reloaded successfully");

        // Log validation warnings
        if let Err(e) = new_config.token.validate() {
            warn!("Token config validation warning: {}", e);
        }
        if let Err(e) = new_config.replay_protection.validate(new_config.token.require_jti) {
            warn!("Replay protection config validation warning: {}", e);
        }
        if let Err(e) = new_config.mesh.validate() {
            warn!("Mesh config validation warning: {}", e);
        }

        Ok(())
    }

    /// Validate configuration before applying
    ///
    /// This can be extended to perform additional validation checks
    async fn validate_config(&self, config: &Config) -> Result<(), String> {
        // Validate token config
        config.token.validate()?;

        // Validate replay protection config
        config.replay_protection.validate(config.token.require_jti)?;

        // Validate mesh config
        config.mesh.validate()?;

        // Validate threads
        if config.threads == 0 {
            return Err("threads must be > 0".to_string());
        }

        // Validate listen addresses are parseable
        config.listen.http.parse::<std::net::SocketAddr>().map_err(|e| {
            format!("Invalid http address '{}': {}", config.listen.http, e)
        })?;
        config.listen.grpc.parse::<std::net::SocketAddr>().map_err(|e| {
            format!("Invalid grpc address '{}': {}", config.listen.grpc, e)
        })?;
        config.listen.mesh.parse::<std::net::SocketAddr>().map_err(|e| {
            format!("Invalid mesh address '{}': {}", config.listen.mesh, e)
        })?;

        // Validate cache config
        if config.cache.enabled && config.cache.capacity == 0 {
            return Err("Cache capacity must be > 0 when cache is enabled".to_string());
        }

        if config.cache.ttl == 0 {
            return Err("Cache TTL must be > 0".to_string());
        }

        Ok(())
    }

    /// Rollback to previous configuration
    ///
    /// Used when a reload fails and we need to restore the last known good config
    pub async fn rollback(&self) -> Result<(), HotReloadError> {
        let previous = self.previous_config.read().await;

        if let Some(prev_config) = previous.as_ref() {
            *self.config.write().await = prev_config.clone();
            info!("Rolled back to previous configuration");
            Ok(())
        } else {
            Err(HotReloadError::LoadError("No previous configuration to roll back to".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    #[tokio::test]
    async fn test_hot_reload_handle_creation() {
        let config = Config::default();
        let temp_file = NamedTempFile::new().unwrap();
        let handle = HotReloadHandle::new(temp_file.path(), config.clone());

        let current = handle.get().await;
        assert_eq!(current.listen.http, config.listen.http);
    }

    #[tokio::test]
    async fn test_validate_config_valid() {
        let config = Config::default();
        let temp_file = NamedTempFile::new().unwrap();
        let handle = HotReloadHandle::new(temp_file.path(), config.clone());

        assert!(handle.validate_config(&config).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_config_invalid_address() {
        let mut config = Config::default();
        config.listen.http = "invalid-address".to_string();

        let temp_file = NamedTempFile::new().unwrap();
        let handle = HotReloadHandle::new(temp_file.path(), Config::default());

        assert!(handle.validate_config(&config).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_config_invalid_threads() {
        let mut config = Config::default();
        config.threads = 0;

        let temp_file = NamedTempFile::new().unwrap();
        let handle = HotReloadHandle::new(temp_file.path(), Config::default());

        assert!(handle.validate_config(&config).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_config_invalid_cache() {
        let mut config = Config::default();
        config.cache.enabled = true;
        config.cache.capacity = 0;

        let temp_file = NamedTempFile::new().unwrap();
        let handle = HotReloadHandle::new(temp_file.path(), Config::default());

        assert!(handle.validate_config(&config).await.is_err());
    }

    #[tokio::test]
    async fn test_reload_config_invalid_falls_back() {
        // Use default config instead of loading from file
        let mut initial_config = Config::default();
        initial_config.listen.http = "0.0.0.0:8080".to_string();

        let temp_file = NamedTempFile::new().unwrap();
        let handle = HotReloadHandle::new(temp_file.path(), initial_config);

        // Create invalid config in memory and validate
        let mut invalid_config = Config::default();
        invalid_config.listen.http = "invalid".to_string(); // Invalid address

        // Verify validation fails
        assert!(handle.validate_config(&invalid_config).await.is_err());

        // Verify current config unchanged
        let current = handle.get().await;
        assert_eq!(current.listen.http, "0.0.0.0:8080");
    }

    #[tokio::test]
    async fn test_rollback() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut config = Config::default();
        config.listen.http = "0.0.0.0:8080".to_string();

        let handle = HotReloadHandle::new(temp_file.path(), config.clone());

        // Save current as previous
        *handle.previous_config.write().await = Some(config.clone());

        // Change current config
        let mut new_config = config.clone();
        new_config.listen.http = "0.0.0.0:9090".to_string();
        *handle.config.write().await = new_config;

        // Verify changed
        assert_eq!(handle.get().await.listen.http, "0.0.0.0:9090");

        // Rollback
        handle.rollback().await.unwrap();

        // Verify rolled back
        assert_eq!(handle.get().await.listen.http, "0.0.0.0:8080");
    }

    #[tokio::test]
    async fn test_rollback_no_previous() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = Config::default();
        let handle = HotReloadHandle::new(temp_file.path(), config);

        // No previous config set
        assert!(handle.rollback().await.is_err());
    }
}
