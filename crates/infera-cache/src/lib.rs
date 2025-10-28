//! # Infera Cache - Caching Layer
//!
//! Optimizes common queries with deterministic caching.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde::{Deserialize, Serialize};

use infera_core::{Decision, CheckRequest};
use infera_store::Revision;

/// Cache key for authorization checks
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckCacheKey {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub revision: Revision,
}

impl From<(&CheckRequest, Revision)> for CheckCacheKey {
    fn from((req, rev): (&CheckRequest, Revision)) -> Self {
        Self {
            subject: req.subject.clone(),
            resource: req.resource.clone(),
            permission: req.permission.clone(),
            revision: rev,
        }
    }
}

/// Cached authorization check result
pub type CheckCacheValue = Decision;

/// In-memory cache for authorization checks
pub struct AuthCache {
    check_cache: Cache<CheckCacheKey, CheckCacheValue>,
}

impl AuthCache {
    pub fn new(max_capacity: u64, ttl: Duration) -> Self {
        let check_cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();

        Self { check_cache }
    }

    /// Get a cached check result
    pub async fn get_check(&self, key: &CheckCacheKey) -> Option<CheckCacheValue> {
        self.check_cache.get(key).await
    }

    /// Cache a check result
    pub async fn put_check(&self, key: CheckCacheKey, value: CheckCacheValue) {
        self.check_cache.insert(key, value).await;
    }

    /// Invalidate cache entries for a specific revision or older
    pub async fn invalidate_before(&self, _revision: Revision) {
        // TODO: Implement selective invalidation
        // For now, we rely on TTL-based expiration
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entry_count: self.check_cache.entry_count(),
            weighted_size: self.check_cache.weighted_size(),
        }
    }
}

impl Default for AuthCache {
    fn default() -> Self {
        Self::new(10_000, Duration::from_secs(300))
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entry_count: u64,
    pub weighted_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use infera_store::Revision;

    #[tokio::test]
    async fn test_cache_operations() {
        let cache = AuthCache::default();

        let key = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        assert!(cache.get_check(&key).await.is_none());

        cache.put_check(key.clone(), Decision::Allow).await;

        assert_eq!(cache.get_check(&key).await, Some(Decision::Allow));
    }
}
