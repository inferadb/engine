//! Integration tests for `SigningKeyCache` against real Ledger.
//!
//! These tests verify that the signing key cache correctly integrates with
//! `LedgerSigningKeyStore` for production-like scenarios.
//!
//! Run with: `RUN_LEDGER_INTEGRATION_TESTS=1 cargo test --test
//! signing_key_cache_ledger_integration`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use ed25519_dalek::SigningKey;
use inferadb_engine_auth::SigningKeyCache;
use inferadb_storage::auth::{PublicSigningKey, PublicSigningKeyStore};
use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig, auth::LedgerSigningKeyStore};
use rand_core::OsRng;

/// Counter for unique namespace IDs to isolate tests.
static NAMESPACE_COUNTER: AtomicI64 = AtomicI64::new(1_000_000);

/// Check if real Ledger integration tests should run.
fn should_run() -> bool {
    env::var("RUN_LEDGER_INTEGRATION_TESTS").is_ok()
}

/// Get the Ledger endpoint from environment, or default.
fn ledger_endpoint() -> String {
    env::var("LEDGER_ENDPOINT").unwrap_or_else(|_| "http://localhost:50051".to_string())
}

/// Get a unique namespace ID for test isolation.
fn unique_namespace_id() -> i64 {
    NAMESPACE_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Generate a valid Ed25519 public key for testing.
fn generate_test_public_key() -> String {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key();
    base64_url_encode(public_key.as_bytes())
}

/// Base64url encode without padding (RFC 7515).
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

/// Create a test PublicSigningKey with valid Ed25519 key material.
fn create_test_key(kid: &str, client_id: i64) -> PublicSigningKey {
    let now = Utc::now();
    PublicSigningKey {
        kid: kid.to_string(),
        public_key: generate_test_public_key(),
        client_id,
        cert_id: 1,
        created_at: now,
        valid_from: now - chrono::Duration::hours(1),
        valid_until: Some(now + chrono::Duration::hours(24)),
        active: true,
        revoked_at: None,
    }
}

/// Create a `LedgerSigningKeyStore` for testing.
async fn create_key_store() -> Arc<dyn PublicSigningKeyStore> {
    let config = LedgerBackendConfig::builder()
        .endpoints(vec![ledger_endpoint()])
        .client_id(format!("test-cache-{}", unique_namespace_id()))
        .namespace_id(1) // Namespace is specified per-operation, not here
        .build()
        .expect("valid config");

    let backend = LedgerBackend::new(config).await.expect("backend creation should succeed");

    Arc::new(LedgerSigningKeyStore::new(backend.client_arc()))
}

#[tokio::test]
async fn test_cache_fetches_key_from_ledger() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("test-key-{}", namespace_id);

    // Store a key in Ledger
    let key = create_test_key(&kid, 1);
    key_store.create_key(namespace_id, &key).await.expect("create_key should succeed");

    // Create cache with short TTL for testing
    let cache = SigningKeyCache::new(key_store.clone(), Duration::from_secs(5));

    // First access should fetch from Ledger (cache miss)
    let decoding_key =
        cache.get_decoding_key(namespace_id, &kid).await.expect("should fetch key from Ledger");

    // Key should be usable (non-empty)
    assert!(!format!("{:?}", decoding_key).is_empty());

    // Second access should be a cache hit
    let decoding_key2 =
        cache.get_decoding_key(namespace_id, &kid).await.expect("should get key from cache");

    // Both keys should be functionally equivalent (same Arc)
    assert!(Arc::ptr_eq(&decoding_key, &decoding_key2));

    // Cleanup
    let _ = key_store.delete_key(namespace_id, &kid).await;
}

#[tokio::test]
async fn test_cache_rejects_revoked_key() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("revoked-key-{}", namespace_id);

    // Store a key in Ledger
    let key = create_test_key(&kid, 1);
    key_store.create_key(namespace_id, &key).await.expect("create_key should succeed");

    // Revoke the key
    key_store
        .revoke_key(namespace_id, &kid, Some("test revocation"))
        .await
        .expect("revoke_key should succeed");

    // Create cache
    let cache = SigningKeyCache::new(key_store.clone(), Duration::from_secs(5));

    // Should reject revoked key
    let result = cache.get_decoding_key(namespace_id, &kid).await;
    assert!(result.is_err(), "should reject revoked key");

    let err = result.unwrap_err();
    let err_msg = format!("{:?}", err);
    assert!(
        err_msg.contains("Revoked") || err_msg.contains("revoked"),
        "error should indicate key is revoked: {}",
        err_msg
    );

    // Cleanup
    let _ = key_store.delete_key(namespace_id, &kid).await;
}

#[tokio::test]
async fn test_cache_rejects_inactive_key() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("inactive-key-{}", namespace_id);

    // Store a key in Ledger
    let key = create_test_key(&kid, 1);
    key_store.create_key(namespace_id, &key).await.expect("create_key should succeed");

    // Deactivate the key
    key_store.deactivate_key(namespace_id, &kid).await.expect("deactivate_key should succeed");

    // Create cache
    let cache = SigningKeyCache::new(key_store.clone(), Duration::from_secs(5));

    // Should reject inactive key
    let result = cache.get_decoding_key(namespace_id, &kid).await;
    assert!(result.is_err(), "should reject inactive key");

    let err = result.unwrap_err();
    let err_msg = format!("{:?}", err);
    assert!(
        err_msg.contains("Inactive") || err_msg.contains("inactive"),
        "error should indicate key is inactive: {}",
        err_msg
    );

    // Cleanup
    let _ = key_store.delete_key(namespace_id, &kid).await;
}

#[tokio::test]
async fn test_cache_rejects_expired_key() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("expired-key-{}", namespace_id);

    // Create an expired key
    let now = Utc::now();
    let expired_key = PublicSigningKey {
        kid: kid.clone(),
        public_key: generate_test_public_key(),
        client_id: 1,
        cert_id: 1,
        created_at: now - chrono::Duration::hours(48),
        valid_from: now - chrono::Duration::hours(48),
        valid_until: Some(now - chrono::Duration::hours(24)), // Expired 24h ago
        active: true,
        revoked_at: None,
    };

    key_store.create_key(namespace_id, &expired_key).await.expect("create_key should succeed");

    // Create cache
    let cache = SigningKeyCache::new(key_store.clone(), Duration::from_secs(5));

    // Should reject expired key
    let result = cache.get_decoding_key(namespace_id, &kid).await;
    assert!(result.is_err(), "should reject expired key");

    let err = result.unwrap_err();
    let err_msg = format!("{:?}", err);
    assert!(
        err_msg.contains("Expired") || err_msg.contains("expired"),
        "error should indicate key is expired: {}",
        err_msg
    );

    // Cleanup
    let _ = key_store.delete_key(namespace_id, &kid).await;
}

#[tokio::test]
async fn test_cache_rejects_not_yet_valid_key() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("future-key-{}", namespace_id);

    // Create a key that's not yet valid
    let now = Utc::now();
    let future_key = PublicSigningKey {
        kid: kid.clone(),
        public_key: generate_test_public_key(),
        client_id: 1,
        cert_id: 1,
        created_at: now,
        valid_from: now + chrono::Duration::hours(24), // Valid in 24h
        valid_until: Some(now + chrono::Duration::hours(48)),
        active: true,
        revoked_at: None,
    };

    key_store.create_key(namespace_id, &future_key).await.expect("create_key should succeed");

    // Create cache
    let cache = SigningKeyCache::new(key_store.clone(), Duration::from_secs(5));

    // Should reject not-yet-valid key
    let result = cache.get_decoding_key(namespace_id, &kid).await;
    assert!(result.is_err(), "should reject not-yet-valid key");

    let err = result.unwrap_err();
    let err_msg = format!("{:?}", err);
    assert!(
        err_msg.contains("NotYetValid") || err_msg.contains("not yet valid"),
        "error should indicate key is not yet valid: {}",
        err_msg
    );

    // Cleanup
    let _ = key_store.delete_key(namespace_id, &kid).await;
}

#[tokio::test]
async fn test_cache_returns_not_found_for_missing_key() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("nonexistent-key-{}", namespace_id);

    // Create cache
    let cache = SigningKeyCache::new(key_store, Duration::from_secs(5));

    // Should return not found error
    let result = cache.get_decoding_key(namespace_id, &kid).await;
    assert!(result.is_err(), "should return error for missing key");

    let err = result.unwrap_err();
    let err_msg = format!("{:?}", err);
    assert!(
        err_msg.contains("NotFound") || err_msg.contains("not found"),
        "error should indicate key not found: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_cache_namespace_isolation() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_1 = unique_namespace_id();
    let namespace_2 = unique_namespace_id();
    let kid = "shared-kid";

    // Store different keys with same KID in different namespaces
    let key1 = create_test_key(kid, 1);
    let key2 = create_test_key(kid, 2); // Different client_id

    key_store.create_key(namespace_1, &key1).await.expect("create_key in ns1 should succeed");
    key_store.create_key(namespace_2, &key2).await.expect("create_key in ns2 should succeed");

    // Create cache
    let cache = SigningKeyCache::new(key_store.clone(), Duration::from_secs(5));

    // Fetch from namespace 1
    let decoding_key_1 =
        cache.get_decoding_key(namespace_1, kid).await.expect("should fetch key from ns1");

    // Fetch from namespace 2
    let decoding_key_2 =
        cache.get_decoding_key(namespace_2, kid).await.expect("should fetch key from ns2");

    // Keys should be different (different public keys)
    assert!(
        !Arc::ptr_eq(&decoding_key_1, &decoding_key_2),
        "keys from different namespaces should be distinct"
    );

    // Cleanup
    let _ = key_store.delete_key(namespace_1, kid).await;
    let _ = key_store.delete_key(namespace_2, kid).await;
}

#[tokio::test]
async fn test_cache_invalidation_refetches_from_ledger() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("invalidate-test-{}", namespace_id);

    // Store a key in Ledger
    let key = create_test_key(&kid, 1);
    key_store.create_key(namespace_id, &key).await.expect("create_key should succeed");

    // Create cache with long TTL
    let cache = SigningKeyCache::new(key_store.clone(), Duration::from_secs(300));

    // First access - populates cache
    let key1 = cache.get_decoding_key(namespace_id, &kid).await.expect("should fetch key");

    // Second access - from cache
    let key2 = cache.get_decoding_key(namespace_id, &kid).await.expect("should get from cache");
    assert!(Arc::ptr_eq(&key1, &key2), "should be same Arc from cache");

    // Invalidate the cache entry
    cache.invalidate(namespace_id, &kid).await;

    // Give the cache time to process the invalidation
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Next access should refetch from Ledger (new Arc)
    let key3 =
        cache.get_decoding_key(namespace_id, &kid).await.expect("should refetch from Ledger");

    // After invalidation, it's a new fetch, so different Arc
    // (The underlying key data is the same, but it's a fresh fetch)
    assert!(!Arc::ptr_eq(&key1, &key3), "should be new Arc after invalidation");

    // Cleanup
    let _ = key_store.delete_key(namespace_id, &kid).await;
}

#[tokio::test]
async fn test_cache_clear_all() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let key_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid1 = format!("clear-test-1-{}", namespace_id);
    let kid2 = format!("clear-test-2-{}", namespace_id);

    // Store two keys
    let key1 = create_test_key(&kid1, 1);
    let key2 = create_test_key(&kid2, 2);
    key_store.create_key(namespace_id, &key1).await.expect("create key1 should succeed");
    key_store.create_key(namespace_id, &key2).await.expect("create key2 should succeed");

    // Create cache
    let cache = SigningKeyCache::new(key_store.clone(), Duration::from_secs(300));

    // Populate cache
    let k1 = cache.get_decoding_key(namespace_id, &kid1).await.expect("fetch key1");
    let k2 = cache.get_decoding_key(namespace_id, &kid2).await.expect("fetch key2");

    // Verify cache is populated
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(cache.entry_count() >= 2, "cache should have at least 2 entries");

    // Clear all
    cache.clear_all().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Cache should be empty
    assert_eq!(cache.entry_count(), 0, "cache should be empty after clear");

    // Refetch should work
    let k1_new = cache.get_decoding_key(namespace_id, &kid1).await.expect("refetch key1");
    assert!(!Arc::ptr_eq(&k1, &k1_new), "should be new Arc after clear_all");

    let k2_new = cache.get_decoding_key(namespace_id, &kid2).await.expect("refetch key2");
    assert!(!Arc::ptr_eq(&k2, &k2_new), "should be new Arc after clear_all");

    // Cleanup
    let _ = key_store.delete_key(namespace_id, &kid1).await;
    let _ = key_store.delete_key(namespace_id, &kid2).await;
}

// =============================================================================
// Ledger Unavailability Fallback Tests
// =============================================================================

/// A wrapper around a real `PublicSigningKeyStore` that can inject failures.
///
/// This allows testing the fallback behavior in integration tests with real
/// Ledger keys by simulating transient errors after successful fetches.
struct FailableStore {
    inner: Arc<dyn PublicSigningKeyStore>,
    failure: std::sync::RwLock<Option<inferadb_storage::StorageError>>,
}

impl FailableStore {
    fn new(inner: Arc<dyn PublicSigningKeyStore>) -> Self {
        Self { inner, failure: std::sync::RwLock::new(None) }
    }

    fn set_failure(&self, failure: Option<inferadb_storage::StorageError>) {
        *self.failure.write().expect("lock") = failure;
    }

    /// Reconstruct error since StorageError doesn't implement Clone
    fn reconstruct_error(error: &inferadb_storage::StorageError) -> inferadb_storage::StorageError {
        match error {
            inferadb_storage::StorageError::Connection { message, .. } => {
                inferadb_storage::StorageError::connection(message)
            },
            inferadb_storage::StorageError::Timeout => {
                inferadb_storage::StorageError::timeout()
            },
            inferadb_storage::StorageError::NotFound { key, .. } => {
                inferadb_storage::StorageError::not_found(key)
            },
            inferadb_storage::StorageError::Internal { message, .. } => {
                inferadb_storage::StorageError::internal(message)
            },
            _ => inferadb_storage::StorageError::internal("unknown error type"),
        }
    }
}

#[async_trait::async_trait]
impl PublicSigningKeyStore for FailableStore {
    async fn create_key(
        &self,
        namespace_id: i64,
        key: &PublicSigningKey,
    ) -> Result<(), inferadb_storage::StorageError> {
        if let Some(ref err) = *self.failure.read().expect("lock") {
            return Err(Self::reconstruct_error(err));
        }
        self.inner.create_key(namespace_id, key).await
    }

    async fn get_key(
        &self,
        namespace_id: i64,
        kid: &str,
    ) -> Result<Option<PublicSigningKey>, inferadb_storage::StorageError> {
        if let Some(ref err) = *self.failure.read().expect("lock") {
            return Err(Self::reconstruct_error(err));
        }
        self.inner.get_key(namespace_id, kid).await
    }

    async fn list_active_keys(
        &self,
        namespace_id: i64,
    ) -> Result<Vec<PublicSigningKey>, inferadb_storage::StorageError> {
        if let Some(ref err) = *self.failure.read().expect("lock") {
            return Err(Self::reconstruct_error(err));
        }
        self.inner.list_active_keys(namespace_id).await
    }

    async fn deactivate_key(
        &self,
        namespace_id: i64,
        kid: &str,
    ) -> Result<(), inferadb_storage::StorageError> {
        if let Some(ref err) = *self.failure.read().expect("lock") {
            return Err(Self::reconstruct_error(err));
        }
        self.inner.deactivate_key(namespace_id, kid).await
    }

    async fn revoke_key(
        &self,
        namespace_id: i64,
        kid: &str,
        reason: Option<&str>,
    ) -> Result<(), inferadb_storage::StorageError> {
        if let Some(ref err) = *self.failure.read().expect("lock") {
            return Err(Self::reconstruct_error(err));
        }
        self.inner.revoke_key(namespace_id, kid, reason).await
    }

    async fn activate_key(
        &self,
        namespace_id: i64,
        kid: &str,
    ) -> Result<(), inferadb_storage::StorageError> {
        if let Some(ref err) = *self.failure.read().expect("lock") {
            return Err(Self::reconstruct_error(err));
        }
        self.inner.activate_key(namespace_id, kid).await
    }

    async fn delete_key(
        &self,
        namespace_id: i64,
        kid: &str,
    ) -> Result<(), inferadb_storage::StorageError> {
        if let Some(ref err) = *self.failure.read().expect("lock") {
            return Err(Self::reconstruct_error(err));
        }
        self.inner.delete_key(namespace_id, kid).await
    }
}

/// Test: Engine handles Ledger unavailability gracefully by using cached keys.
///
/// This test validates that when Ledger becomes unavailable after a key was
/// successfully fetched, the Engine falls back to the previously cached key
/// for transient errors (connection failures, timeouts).
///
/// This test addresses PRD Task 8 acceptance criteria:
/// "Test: Engine handles Ledger unavailability gracefully (use cached keys)"
#[tokio::test]
async fn test_ledger_unavailability_fallback_integration() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let inner_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("fallback-integration-{}", namespace_id);

    // Store a key in real Ledger
    let key = create_test_key(&kid, 1);
    inner_store.create_key(namespace_id, &key).await.expect("create_key should succeed");

    // Wrap with failable store
    let failable_store = Arc::new(FailableStore::new(inner_store.clone()));

    // Create cache with short TTL for testing
    let cache = SigningKeyCache::new(
        Arc::clone(&failable_store) as Arc<dyn PublicSigningKeyStore>,
        Duration::from_secs(1), // Short TTL so we can test cache expiry
    );

    // First access should fetch from real Ledger (cache miss)
    let _decoding_key =
        cache.get_decoding_key(namespace_id, &kid).await.expect("initial fetch should succeed");

    // Simulate Ledger becoming unavailable (connection error)
    failable_store
        .set_failure(Some(inferadb_storage::StorageError::connection("simulated network failure")));

    // Clear the TTL cache to force a "refetch" attempt
    cache.clear_all().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Should fall back to cached key despite Ledger being unavailable
    let fallback_key = cache
        .get_decoding_key(namespace_id, &kid)
        .await
        .expect("should use fallback cache when Ledger is unavailable");

    // Keys should be functionally equivalent (both valid decoding keys)
    // Note: They may not be the same Arc since fallback map returns a clone
    assert!(!format!("{:?}", fallback_key).is_empty(), "fallback key should be valid");

    // Restore Ledger connectivity
    failable_store.set_failure(None);

    // Clear cache again and verify we can fetch fresh
    cache.clear_all().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let fresh_key = cache
        .get_decoding_key(namespace_id, &kid)
        .await
        .expect("should fetch fresh key after Ledger recovery");

    assert!(!format!("{:?}", fresh_key).is_empty(), "fresh key should be valid");

    // Cleanup
    let _ = inner_store.delete_key(namespace_id, &kid).await;
}

/// Test: Timeout errors also trigger fallback behavior.
///
/// Validates that timeout errors (a type of transient failure) correctly
/// trigger the fallback mechanism for Ledger-backed keys.
#[tokio::test]
async fn test_ledger_timeout_fallback_integration() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let inner_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("timeout-fallback-{}", namespace_id);

    // Store a key in real Ledger
    let key = create_test_key(&kid, 1);
    inner_store.create_key(namespace_id, &key).await.expect("create_key should succeed");

    // Wrap with failable store
    let failable_store = Arc::new(FailableStore::new(inner_store.clone()));

    let cache = SigningKeyCache::new(
        Arc::clone(&failable_store) as Arc<dyn PublicSigningKeyStore>,
        Duration::from_secs(1),
    );

    // Initial successful fetch
    let _ = cache.get_decoding_key(namespace_id, &kid).await.expect("initial fetch should succeed");

    // Simulate timeout
    failable_store.set_failure(Some(inferadb_storage::StorageError::timeout()));

    // Clear TTL cache
    cache.clear_all().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Should use fallback on timeout
    let fallback_key =
        cache.get_decoding_key(namespace_id, &kid).await.expect("should use fallback on timeout");

    assert!(!format!("{:?}", fallback_key).is_empty(), "fallback key should be valid");

    // Cleanup
    failable_store.set_failure(None);
    let _ = inner_store.delete_key(namespace_id, &kid).await;
}

/// Test: Non-transient errors do NOT trigger fallback (security requirement).
///
/// Validates that internal errors (non-transient) are NOT masked by fallback
/// behavior. This is important for security - if the Ledger explicitly returns
/// an error about the key, we should not serve a potentially stale cached version.
#[tokio::test]
async fn test_non_transient_error_no_fallback_integration() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let inner_store = create_key_store().await;
    let namespace_id = unique_namespace_id();
    let kid = format!("no-fallback-{}", namespace_id);

    // Store a key in real Ledger
    let key = create_test_key(&kid, 1);
    inner_store.create_key(namespace_id, &key).await.expect("create_key should succeed");

    // Wrap with failable store
    let failable_store = Arc::new(FailableStore::new(inner_store.clone()));

    let cache = SigningKeyCache::new(
        Arc::clone(&failable_store) as Arc<dyn PublicSigningKeyStore>,
        Duration::from_secs(1),
    );

    // Initial successful fetch
    let _ = cache.get_decoding_key(namespace_id, &kid).await.expect("initial fetch should succeed");

    // Simulate internal error (non-transient)
    failable_store
        .set_failure(Some(inferadb_storage::StorageError::internal("database corruption")));

    // Clear TTL cache
    cache.clear_all().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Should NOT use fallback for internal errors
    let result = cache.get_decoding_key(namespace_id, &kid).await;
    assert!(result.is_err(), "should NOT use fallback for non-transient internal errors");

    // Cleanup
    failable_store.set_failure(None);
    let _ = inner_store.delete_key(namespace_id, &kid).await;
}
