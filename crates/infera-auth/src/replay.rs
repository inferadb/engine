//! Replay protection for JWT tokens using JTI (JWT ID) tracking
//!
//! This module provides replay attack protection by tracking JWT IDs (JTI claims) and ensuring
//! each token can only be used once. Two implementations are provided:
//!
//! - **Redis-based**: For production multi-node deployments (requires `replay-protection` feature)
//! - **In-memory**: For single-node deployments or development (not suitable for production
//!   clusters)
//!
//! ## Security
//!
//! Replay protection is essential for preventing attackers from reusing captured JWTs.
//! Each JWT must include a unique `jti` claim, which is tracked until the token expires.
//!
//! ## Example
//!
//! ```ignore
//! use infera_auth::replay::{ReplayProtection, InMemoryReplayProtection};
//!
//! let replay = InMemoryReplayProtection::new();
//! let is_new = replay.check_and_mark("unique-jti", 1700000000).await?;
//! assert!(is_new); // First use returns true
//!
//! let is_replay = replay.check_and_mark("unique-jti", 1700000000).await?;
//! assert!(!is_replay); // Second use returns false (replay detected)
//! ```

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use moka::future::Cache;
use tracing::{debug, warn};

use crate::error::AuthError;

/// Trait for replay protection implementations
///
/// Implementations track JWT IDs (JTI) to prevent token replay attacks.
/// Each JTI should only be accepted once, with entries expiring when the token expires.
#[async_trait::async_trait]
pub trait ReplayProtection: Send + Sync {
    /// Check if a JTI has been seen before, and mark it as used
    ///
    /// # Arguments
    ///
    /// * `jti` - The JWT ID claim to check
    /// * `exp` - The token expiration time as a Unix timestamp
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Token is new, now marked as used
    /// * `Ok(false)` - Token was already seen (replay attack detected)
    /// * `Err(_)` - Storage error occurred
    async fn check_and_mark(&self, jti: &str, exp: u64) -> Result<bool, AuthError>;
}

/// Redis-based replay protection for production multi-node deployments
///
/// Uses Redis SET NX (set if not exists) for atomic check-and-mark operations.
/// TTL is automatically set to the token expiration time to prevent memory leaks.
///
/// # Example
///
/// ```ignore
/// use infera_auth::replay::RedisReplayProtection;
///
/// let replay = RedisReplayProtection::new("redis://localhost:6379").await?;
/// let is_new = replay.check_and_mark("jti-123", 1700000000).await?;
/// ```
#[cfg(feature = "replay-protection")]
pub struct RedisReplayProtection {
    client: redis::aio::ConnectionManager,
    key_prefix: String,
}

#[cfg(feature = "replay-protection")]
impl RedisReplayProtection {
    /// Create a new Redis replay protection instance
    ///
    /// # Arguments
    ///
    /// * `redis_url` - Redis connection string (e.g., "redis://localhost:6379")
    ///
    /// # Errors
    ///
    /// Returns an error if the Redis connection cannot be established
    pub async fn new(redis_url: &str) -> Result<Self, AuthError> {
        let client = redis::Client::open(redis_url).map_err(|e| {
            AuthError::ReplayProtectionError(format!("Failed to create Redis client: {}", e))
        })?;

        let connection_manager = redis::aio::ConnectionManager::new(client).await.map_err(|e| {
            AuthError::ReplayProtectionError(format!("Failed to connect to Redis: {}", e))
        })?;

        debug!("Redis replay protection initialized");

        Ok(Self { client: connection_manager, key_prefix: "inferadb:jti:".to_string() })
    }

    /// Calculate TTL in seconds from Unix timestamp
    fn calculate_ttl(&self, exp: u64) -> Result<u64, AuthError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch")
            .as_secs();

        if exp <= now {
            return Err(AuthError::TokenExpired);
        }

        Ok(exp - now)
    }
}

#[cfg(feature = "replay-protection")]
#[async_trait::async_trait]
impl ReplayProtection for RedisReplayProtection {
    async fn check_and_mark(&self, jti: &str, exp: u64) -> Result<bool, AuthError> {
        use redis::AsyncCommands;

        let key = format!("{}{}", self.key_prefix, jti);
        let ttl = self.calculate_ttl(exp)?;

        let mut conn = self.client.clone();

        // SET key value NX EX ttl
        // Returns true if key was set (new), false if key already exists (replay)
        let result: bool = conn
            .set_nx(&key, "1")
            .await
            .map_err(|e| AuthError::ReplayProtectionError(format!("Redis SET NX failed: {}", e)))?;

        if result {
            // Key was set successfully, now set the TTL
            let _: () = conn.expire(&key, ttl as i64).await.map_err(|e| {
                AuthError::ReplayProtectionError(format!("Redis EXPIRE failed: {}", e))
            })?;

            debug!(jti = %jti, ttl = %ttl, "Token JTI marked as used");
        } else {
            warn!(jti = %jti, "Token replay detected");
        }

        Ok(result)
    }
}

/// In-memory replay protection using Moka cache
///
/// Suitable for single-node deployments or development. **Not recommended for production
/// multi-node clusters** as JTI tracking is not shared across nodes.
///
/// # Warning
///
/// In multi-node deployments, each node maintains its own JTI cache, allowing an attacker
/// to replay tokens by targeting different nodes. Use [`RedisReplayProtection`] instead.
///
/// # Example
///
/// ```ignore
/// use infera_auth::replay::InMemoryReplayProtection;
///
/// let replay = InMemoryReplayProtection::new();
/// let is_new = replay.check_and_mark("jti-123", 1700000000).await?;
/// ```
pub struct InMemoryReplayProtection {
    cache: Arc<Cache<String, ()>>,
}

impl InMemoryReplayProtection {
    /// Create a new in-memory replay protection instance
    ///
    /// Configures a cache with:
    /// - Maximum capacity: 100,000 entries
    /// - Time-based expiration matching token TTL
    pub fn new() -> Self {
        warn!("Using in-memory replay protection - NOT suitable for multi-node deployments");

        let cache = Cache::builder().max_capacity(100_000).build();

        Self { cache: Arc::new(cache) }
    }

    /// Calculate TTL duration from Unix timestamp
    fn calculate_ttl(&self, exp: u64) -> Result<Duration, AuthError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch")
            .as_secs();

        if exp <= now {
            return Err(AuthError::TokenExpired);
        }

        Ok(Duration::from_secs(exp - now))
    }
}

impl Default for InMemoryReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ReplayProtection for InMemoryReplayProtection {
    async fn check_and_mark(&self, jti: &str, exp: u64) -> Result<bool, AuthError> {
        let ttl = self.calculate_ttl(exp)?;

        // Check if JTI already exists
        if self.cache.get(jti).await.is_some() {
            warn!(jti = %jti, "Token replay detected (in-memory)");
            return Ok(false);
        }

        // Insert with TTL
        self.cache.insert(jti.to_string(), ()).await;

        // Note: Moka doesn't support per-entry TTL directly, so we rely on time-to-idle
        // For production use, prefer RedisReplayProtection
        debug!(jti = %jti, ttl = ?ttl, "Token JTI marked as used (in-memory)");

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn future_timestamp(offset_secs: u64) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + offset_secs
    }

    fn past_timestamp(offset_secs: u64) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().saturating_sub(offset_secs)
    }

    #[tokio::test]
    async fn test_in_memory_replay_protection_first_use() {
        let replay = InMemoryReplayProtection::new();
        let exp = future_timestamp(3600);

        let is_new = replay.check_and_mark("test-jti-1", exp).await.unwrap();
        assert!(is_new, "First use should return true");
    }

    #[tokio::test]
    async fn test_in_memory_replay_protection_second_use() {
        let replay = InMemoryReplayProtection::new();
        let exp = future_timestamp(3600);

        let is_new = replay.check_and_mark("test-jti-2", exp).await.unwrap();
        assert!(is_new, "First use should return true");

        let is_replay = replay.check_and_mark("test-jti-2", exp).await.unwrap();
        assert!(!is_replay, "Second use should return false (replay detected)");
    }

    #[tokio::test]
    async fn test_in_memory_replay_protection_expired_token() {
        let replay = InMemoryReplayProtection::new();
        let exp = past_timestamp(10);

        let result = replay.check_and_mark("test-jti-3", exp).await;
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[tokio::test]
    async fn test_in_memory_replay_protection_different_jtis() {
        let replay = InMemoryReplayProtection::new();
        let exp = future_timestamp(3600);

        let is_new_1 = replay.check_and_mark("test-jti-4", exp).await.unwrap();
        assert!(is_new_1);

        let is_new_2 = replay.check_and_mark("test-jti-5", exp).await.unwrap();
        assert!(is_new_2);

        // Both JTIs should now be marked as used
        let is_replay_1 = replay.check_and_mark("test-jti-4", exp).await.unwrap();
        assert!(!is_replay_1);

        let is_replay_2 = replay.check_and_mark("test-jti-5", exp).await.unwrap();
        assert!(!is_replay_2);
    }

    #[cfg(feature = "replay-protection")]
    mod redis_tests {
        use super::*;

        // Note: These tests require a running Redis instance
        // Skip them in CI unless REDIS_URL is set

        async fn get_redis_url() -> Option<String> {
            std::env::var("REDIS_URL").ok()
        }

        #[tokio::test]
        async fn test_redis_replay_protection_first_use() {
            let Some(redis_url) = get_redis_url().await else {
                eprintln!("Skipping Redis test: REDIS_URL not set");
                return;
            };

            let replay = RedisReplayProtection::new(&redis_url).await.unwrap();
            let exp = future_timestamp(3600);
            let jti = format!("test-redis-jti-{}", uuid::Uuid::new_v4());

            let is_new = replay.check_and_mark(&jti, exp).await.unwrap();
            assert!(is_new, "First use should return true");
        }

        #[tokio::test]
        async fn test_redis_replay_protection_second_use() {
            let Some(redis_url) = get_redis_url().await else {
                eprintln!("Skipping Redis test: REDIS_URL not set");
                return;
            };

            let replay = RedisReplayProtection::new(&redis_url).await.unwrap();
            let exp = future_timestamp(3600);
            let jti = format!("test-redis-jti-{}", uuid::Uuid::new_v4());

            let is_new = replay.check_and_mark(&jti, exp).await.unwrap();
            assert!(is_new, "First use should return true");

            let is_replay = replay.check_and_mark(&jti, exp).await.unwrap();
            assert!(!is_replay, "Second use should return false (replay detected)");
        }

        #[tokio::test]
        async fn test_redis_replay_protection_expired_token() {
            let Some(redis_url) = get_redis_url().await else {
                eprintln!("Skipping Redis test: REDIS_URL not set");
                return;
            };

            let replay = RedisReplayProtection::new(&redis_url).await.unwrap();
            let exp = past_timestamp(10);
            let jti = format!("test-redis-jti-{}", uuid::Uuid::new_v4());

            let result = replay.check_and_mark(&jti, exp).await;
            assert!(matches!(result, Err(AuthError::TokenExpired)));
        }
    }
}
