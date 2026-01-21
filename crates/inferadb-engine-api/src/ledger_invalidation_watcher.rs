//! Ledger-based cache invalidation watcher for Engine.
//!
//! This module watches for block commits in Ledger and invalidates the appropriate
//! Engine caches in response using a simple, database-native approach.
//!
//! # Architecture
//!
//! Engine subscribes to Ledger's `WatchBlocks` gRPC stream:
//! 1. Receives block announcements when any data changes in the watched vault
//! 2. Invalidates auth cache on each block commit
//! 3. Handles stream disconnection with automatic reconnection (provided by SDK)
//!
//! # Why Block-Level Granularity
//!
//! The Ledger watcher invalidates on any block commit. This is:
//! - **Simpler**: No event parsing, no log reading, no version tracking
//! - **Complete**: Catches ALL mutations (from Engine AND Control)
//! - **Decoupled**: Engine doesn't depend on Control for cache correctness
//!
//! The trade-off is slightly coarser invalidation (any write triggers cache clear),
//! but with sub-millisecond cache rebuilds this is acceptable.

use std::sync::Arc;

use futures::StreamExt;
use inferadb_engine_cache::AuthCache;
use inferadb_ledger_sdk::{ClientConfig, LedgerClient};
use tokio::{sync::watch, task::JoinHandle};
use tracing::{debug, error, info, warn};

/// Configuration for the Ledger invalidation watcher.
#[derive(Debug, Clone)]
pub struct LedgerWatcherConfig {
    /// Ledger server endpoint URL.
    pub endpoint: String,
    /// Client ID for the watcher connection.
    pub client_id: String,
    /// Namespace ID to watch.
    pub namespace_id: i64,
    /// Vault ID to watch.
    pub vault_id: i64,
}

/// Ledger-based cache invalidation watcher.
///
/// Watches for block commits in Ledger and applies cache invalidations to Engine caches.
/// Uses Ledger SDK's built-in reconnection with exponential backoff.
pub struct LedgerInvalidationWatcher {
    /// Ledger client for WatchBlocks subscription.
    client: LedgerClient,
    /// Namespace ID to watch.
    namespace_id: i64,
    /// Vault ID to watch.
    vault_id: i64,
    /// Auth cache to invalidate.
    auth_cache: Arc<AuthCache>,
}

impl LedgerInvalidationWatcher {
    /// Create a new Ledger invalidation watcher from configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Watcher configuration (endpoint, namespace, vault)
    /// * `auth_cache` - Auth cache to invalidate on block commits
    ///
    /// # Errors
    ///
    /// Returns an error if the Ledger client cannot be created.
    pub async fn new(
        config: LedgerWatcherConfig,
        auth_cache: Arc<AuthCache>,
    ) -> Result<Self, String> {
        let client_config = ClientConfig::builder()
            .with_endpoint(&config.endpoint)
            .with_client_id(&config.client_id)
            .build()
            .map_err(|e| format!("Failed to build Ledger client config: {e}"))?;

        let client = LedgerClient::new(client_config)
            .await
            .map_err(|e| format!("Failed to connect to Ledger for watcher: {e}"))?;

        Ok(Self {
            client,
            namespace_id: config.namespace_id,
            vault_id: config.vault_id,
            auth_cache,
        })
    }

    /// Start the background watch loop.
    ///
    /// Returns a tuple containing:
    /// - `JoinHandle`: Can be used to await or abort the watcher
    /// - `watch::Sender<()>`: Send a message to gracefully stop the watcher
    ///
    /// # Example
    ///
    /// ```ignore
    /// let watcher = LedgerInvalidationWatcher::new(...);
    /// let (handle, shutdown) = watcher.start();
    ///
    /// // Later, to stop:
    /// shutdown.send(()).ok();
    /// handle.await.ok();
    /// ```
    pub fn start(self) -> (JoinHandle<()>, watch::Sender<()>) {
        info!(
            namespace_id = self.namespace_id,
            vault_id = self.vault_id,
            "Starting Ledger cache invalidation watcher"
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(());

        let handle = tokio::spawn(async move {
            self.watch_loop(shutdown_rx).await;
        });

        (handle, shutdown_tx)
    }

    /// Main watch loop that subscribes to block announcements.
    async fn watch_loop(&self, mut shutdown_rx: watch::Receiver<()>) {
        // Start watching from height 1 (or we could track last seen height in the future)
        let mut last_height = 0u64;

        loop {
            // Check for shutdown signal
            if shutdown_rx.has_changed().unwrap_or(false) {
                info!("Ledger invalidation watcher received shutdown signal");
                break;
            }

            match self.watch_and_process(last_height + 1, &mut shutdown_rx).await {
                Ok(height) => {
                    // Update last seen height for resume on reconnection
                    last_height = height;
                    debug!(last_height, "Ledger watch stream ended, will reconnect");
                },
                Err(e) => {
                    // The SDK handles reconnection internally, but log unexpected errors
                    error!(error = %e, "Ledger invalidation watch error");
                    // Brief pause before retry to avoid tight loops on persistent errors
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                },
            }
        }
    }

    /// Watch for block commits and process invalidations.
    ///
    /// Returns the last height processed when the stream ends.
    async fn watch_and_process(
        &self,
        start_height: u64,
        shutdown_rx: &mut watch::Receiver<()>,
    ) -> Result<u64, String> {
        let mut stream = self
            .client
            .watch_blocks(self.namespace_id, self.vault_id, start_height)
            .await
            .map_err(|e| format!("Failed to subscribe to WatchBlocks: {e}"))?;

        let mut last_height = start_height.saturating_sub(1);

        loop {
            tokio::select! {
                // Check for shutdown
                _ = shutdown_rx.changed() => {
                    info!("Shutdown received during watch");
                    return Ok(last_height);
                }
                // Process next block announcement
                announcement = stream.next() => {
                    match announcement {
                        Some(Ok(block)) => {
                            debug!(
                                height = block.height,
                                namespace_id = block.namespace_id,
                                vault_id = block.vault_id,
                                "Received block announcement, invalidating caches"
                            );

                            // Invalidate caches on any block commit
                            self.invalidate_all_caches(block.vault_id).await;

                            last_height = block.height;
                        },
                        Some(Err(e)) => {
                            warn!(error = %e, "Error in WatchBlocks stream");
                            // Continue - SDK will attempt reconnection
                        },
                        None => {
                            // Stream ended
                            debug!("WatchBlocks stream ended");
                            return Ok(last_height);
                        },
                    }
                }
            }
        }
    }

    /// Invalidate all relevant caches for a vault.
    ///
    /// This is a coarse-grained invalidation triggered by any block commit.
    /// In the future, we could parse block contents for finer-grained invalidation.
    async fn invalidate_all_caches(&self, vault_id: i64) {
        // Invalidate auth cache for this vault
        self.auth_cache.invalidate_vault(vault_id).await;

        // Note: In the Ledger-based architecture, signing keys are stored in Ledger
        // and the SigningKeyCache uses TTL-based expiration. No explicit invalidation
        // is needed here since keys are fetched fresh from Ledger on cache miss.
    }
}

#[cfg(test)]
mod tests {
    // Integration tests require a running Ledger instance.
    // See tests/ledger_integration.rs for full integration tests.
    // Unit tests for the watcher logic are limited since it primarily
    // coordinates between Ledger SDK streams and cache invalidation.
}
