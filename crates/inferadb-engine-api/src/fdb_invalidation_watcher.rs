//! FDB-based cache invalidation watcher for Engine.
//!
//! This module watches for invalidation events published by Control to FDB
//! and invalidates the appropriate Engine caches in response.
//!
//! # Architecture
//!
//! Control writes invalidation events to FDB when data changes:
//! 1. Atomically increments `inferadb/invalidation/version` (triggers watches)
//! 2. Writes event details to `inferadb/invalidation-log/{timestamp}:{event_id}`
//!
//! Engine watches the version key and processes new events:
//! 1. Watch triggers when version changes
//! 2. Read events from log since last processed timestamp
//! 3. Apply invalidations to local caches
//! 4. Update last processed timestamp

use std::sync::Arc;

use chrono::Utc;
use foundationdb::Database;
use inferadb_engine_auth::CertificateCache;
use inferadb_engine_cache::AuthCache;
use inferadb_engine_control_client::ControlVaultVerifier;
use inferadb_engine_fdb_shared::{
    INVALIDATION_LOG_PREFIX, INVALIDATION_VERSION_KEY, InvalidationEvent, InvalidationLogEntry,
};
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::{debug, error, info, warn};

/// FDB-based cache invalidation watcher.
///
/// Watches for invalidation events from Control and applies them to Engine caches.
pub struct FdbInvalidationWatcher {
    db: Arc<Database>,
    auth_cache: Arc<AuthCache>,
    vault_verifier: Option<Arc<ControlVaultVerifier>>,
    cert_cache: Option<Arc<CertificateCache>>,
    /// Last processed event timestamp (milliseconds)
    last_processed_ms: RwLock<i64>,
}

impl FdbInvalidationWatcher {
    /// Create a new FDB invalidation watcher.
    pub fn new(
        db: Arc<Database>,
        auth_cache: Arc<AuthCache>,
        vault_verifier: Option<Arc<ControlVaultVerifier>>,
        cert_cache: Option<Arc<CertificateCache>>,
    ) -> Self {
        Self {
            db,
            auth_cache,
            vault_verifier,
            cert_cache,
            // Start from now - we don't need to replay old events
            last_processed_ms: RwLock::new(Utc::now().timestamp_millis()),
        }
    }

    /// Start the background watch loop.
    ///
    /// Returns a JoinHandle that can be used to await or abort the watcher.
    pub fn start(self: Arc<Self>) -> JoinHandle<()> {
        info!("Starting FDB cache invalidation watcher");
        tokio::spawn(async move {
            self.watch_loop().await;
        })
    }

    /// Main watch loop that watches for version changes.
    async fn watch_loop(&self) {
        loop {
            match self.watch_and_process().await {
                Ok(()) => {
                    // Watch completed normally (version changed), continue looping
                    debug!("Invalidation watch triggered, processing events");
                },
                Err(e) => {
                    // Log error and retry after a delay
                    error!(error = %e, "FDB invalidation watch error, retrying in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                },
            }
        }
    }

    /// Watch for version changes and process new events.
    async fn watch_and_process(&self) -> Result<(), String> {
        let db = Arc::clone(&self.db);

        // Create a watch on the version key
        let watch_fut = db
            .run(|trx, _maybe_committed| async move {
                // Read current version and set up watch
                let _current_version = trx.get(INVALIDATION_VERSION_KEY, false).await?;
                let watch = trx.watch(INVALIDATION_VERSION_KEY);
                Ok(watch)
            })
            .await
            .map_err(|e| format!("Failed to set up invalidation watch: {e}"))?;

        // Wait for the watch to trigger (version changed)
        watch_fut.await.map_err(|e| format!("Watch future failed: {e}"))?;

        // Version changed, read and process new events
        self.process_new_events().await
    }

    /// Read and process new events from the invalidation log.
    async fn process_new_events(&self) -> Result<(), String> {
        let last_ms = *self.last_processed_ms.read().await;
        let now_ms = Utc::now().timestamp_millis();

        // Build range to read: from last processed time to now
        let start_key = build_log_key(last_ms, "");
        let end_key = build_log_key(now_ms + 1, ""); // +1 to include current millisecond

        let db = Arc::clone(&self.db);
        let events = db
            .run({
                let start_key = start_key.clone();
                let end_key = end_key.clone();
                move |trx, _maybe_committed| {
                    let start_key = start_key.clone();
                    let end_key = end_key.clone();
                    async move {
                        let range = trx
                            .get_range(
                                &foundationdb::RangeOption {
                                    begin: foundationdb::KeySelector::first_greater_or_equal(
                                        &start_key,
                                    ),
                                    end: foundationdb::KeySelector::first_greater_or_equal(
                                        &end_key,
                                    ),
                                    limit: Some(1000), // Process up to 1000 events at a time
                                    ..Default::default()
                                },
                                1,    // iteration
                                true, // snapshot
                            )
                            .await?;

                        let mut entries = Vec::new();
                        for kv in range.iter() {
                            if let Ok(entry) =
                                serde_json::from_slice::<InvalidationLogEntry>(kv.value())
                            {
                                entries.push(entry);
                            }
                        }
                        Ok(entries)
                    }
                }
            })
            .await
            .map_err(|e| format!("Failed to read invalidation events: {e}"))?;

        if events.is_empty() {
            debug!("No new invalidation events to process");
            return Ok(());
        }

        info!(count = events.len(), "Processing invalidation events");

        // Track the latest timestamp we processed
        let mut max_timestamp = last_ms;

        for entry in events {
            if entry.timestamp_ms > max_timestamp {
                max_timestamp = entry.timestamp_ms;
            }

            self.apply_invalidation(&entry.event).await;
        }

        // Update last processed timestamp
        *self.last_processed_ms.write().await = max_timestamp + 1;

        Ok(())
    }

    /// Apply a single invalidation event to caches.
    async fn apply_invalidation(&self, event: &InvalidationEvent) {
        match event {
            InvalidationEvent::Vault { vault_id } => {
                info!(vault_id = %vault_id, "Invalidating vault cache");

                // Invalidate auth cache for this vault
                self.auth_cache.invalidate_vault(*vault_id).await;

                // Invalidate vault verifier cache if available
                if let Some(verifier) = &self.vault_verifier {
                    verifier.invalidate_vault(*vault_id).await;
                }
            },

            InvalidationEvent::Organization { org_id } => {
                info!(org_id = %org_id, "Invalidating organization cache");

                // Invalidate vault verifier's organization cache if available
                if let Some(verifier) = &self.vault_verifier {
                    verifier.invalidate_organization(*org_id).await;
                }

                // Note: We don't invalidate auth_cache here because it's keyed by vault_id,
                // not org_id. Organization invalidation affects vault lookup, not authz decisions.
            },

            InvalidationEvent::Certificate { org_id, client_id, cert_id } => {
                info!(
                    org_id = %org_id,
                    client_id = %client_id,
                    cert_id = %cert_id,
                    "Invalidating certificate cache"
                );

                // Invalidate certificate cache if available
                if let Some(cert_cache) = &self.cert_cache {
                    cert_cache.invalidate(*org_id, *client_id, *cert_id).await;
                }
            },

            InvalidationEvent::All => {
                warn!("Received invalidate-all event, clearing all caches");

                // Invalidate all auth cache entries
                self.auth_cache.invalidate_all().await;

                // Invalidate all vault verifier caches if available
                if let Some(verifier) = &self.vault_verifier {
                    verifier.clear_all_caches().await;
                }

                // Invalidate all certificate cache entries if available
                if let Some(cert_cache) = &self.cert_cache {
                    cert_cache.clear_all().await;
                }
            },
        }
    }
}

/// Build an invalidation log key from timestamp and event ID.
fn build_log_key(timestamp_ms: i64, event_id: &str) -> Vec<u8> {
    let mut key = INVALIDATION_LOG_PREFIX.to_vec();
    // Zero-pad timestamp to ensure proper lexicographic ordering
    key.extend_from_slice(format!("{:020}:", timestamp_ms).as_bytes());
    key.extend_from_slice(event_id.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use inferadb_engine_fdb_shared::parse_invalidation_log_key;

    use super::*;

    #[test]
    fn test_build_log_key() {
        let key = build_log_key(1699999999000, "abc-123");
        // 20-digit zero-padded timestamp for proper lexicographic ordering
        let expected = b"inferadb/invalidation-log/00000001699999999000:abc-123";
        assert_eq!(key, expected.to_vec());
    }

    #[test]
    fn test_build_log_key_ordering() {
        // Earlier timestamp should come before later timestamp
        let key1 = build_log_key(1000, "a");
        let key2 = build_log_key(2000, "b");
        assert!(key1 < key2);

        // Same timestamp, different event IDs
        let key3 = build_log_key(1000, "aaa");
        let key4 = build_log_key(1000, "bbb");
        assert!(key3 < key4);
    }

    #[test]
    fn test_parse_invalidation_log_key_roundtrip() {
        let timestamp = 1699999999000i64;
        let key = build_log_key(timestamp, "test-event");
        let parsed = parse_invalidation_log_key(&key);
        assert_eq!(parsed, Some(timestamp));
    }
}
