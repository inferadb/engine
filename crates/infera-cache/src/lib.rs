//! # Infera Cache - Caching Layer
//!
//! Optimizes common queries with deterministic caching.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use moka::future::Cache;
use serde::{Deserialize, Serialize};

use infera_store::Revision;

/// Authorization decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
}

/// Cache key for authorization checks
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckCacheKey {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub revision: Revision,
}

impl CheckCacheKey {
    pub fn new(subject: String, resource: String, permission: String, revision: Revision) -> Self {
        Self {
            subject,
            resource,
            permission,
            revision,
        }
    }
}

/// Cached authorization check result
pub type CheckCacheValue = Decision;

/// Cache key for expand operations (intermediate results)
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpandCacheKey {
    pub object: String,
    pub relation: String,
    pub revision: Revision,
}

impl ExpandCacheKey {
    pub fn new(object: String, relation: String, revision: Revision) -> Self {
        Self {
            object,
            relation,
            revision,
        }
    }
}

/// Cached expand result (list of users)
pub type ExpandCacheValue = Vec<String>;

/// In-memory cache for authorization checks
pub struct AuthCache {
    check_cache: Cache<CheckCacheKey, CheckCacheValue>,
    expand_cache: Cache<ExpandCacheKey, ExpandCacheValue>,
    hits: AtomicU64,
    misses: AtomicU64,
    expand_hits: AtomicU64,
    expand_misses: AtomicU64,
    invalidations: AtomicU64,
}

impl AuthCache {
    pub fn new(max_capacity: u64, ttl: Duration) -> Self {
        let check_cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();

        let expand_cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();

        Self {
            check_cache,
            expand_cache,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            expand_hits: AtomicU64::new(0),
            expand_misses: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
        }
    }

    /// Get a cached check result
    pub async fn get_check(&self, key: &CheckCacheKey) -> Option<CheckCacheValue> {
        let result = self.check_cache.get(key).await;
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Cache a check result
    pub async fn put_check(&self, key: CheckCacheKey, value: CheckCacheValue) {
        self.check_cache.insert(key, value).await;
    }

    /// Get a cached expand result
    pub async fn get_expand(&self, key: &ExpandCacheKey) -> Option<ExpandCacheValue> {
        let result = self.expand_cache.get(key).await;
        if result.is_some() {
            self.expand_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.expand_misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Cache an expand result
    pub async fn put_expand(&self, key: ExpandCacheKey, value: ExpandCacheValue) {
        self.expand_cache.insert(key, value).await;
    }

    /// Invalidate all cache entries
    pub async fn invalidate_all(&self) {
        self.check_cache.invalidate_all();
        self.expand_cache.invalidate_all();
        self.invalidations.fetch_add(1, Ordering::Relaxed);
    }

    /// Invalidate cache entries for a specific revision or older
    pub async fn invalidate_before(&self, _revision: Revision) {
        // Iterate through all entries and remove those with older revisions
        // Note: This is not the most efficient approach but works for now
        // A better approach would be to maintain a secondary index
        let _count = 0;
        self.check_cache.run_pending_tasks().await;
        self.expand_cache.run_pending_tasks().await;

        // Since moka doesn't provide an efficient way to iterate and conditionally remove,
        // we'll invalidate all entries when a write occurs
        // This is conservative but correct
        self.check_cache.invalidate_all();
        self.expand_cache.invalidate_all();
        self.invalidations.fetch_add(1, Ordering::Relaxed);
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let expand_hits = self.expand_hits.load(Ordering::Relaxed);
        let expand_misses = self.expand_misses.load(Ordering::Relaxed);

        let total_requests = hits + misses;
        let hit_rate = if total_requests > 0 {
            (hits as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        let expand_total_requests = expand_hits + expand_misses;
        let expand_hit_rate = if expand_total_requests > 0 {
            (expand_hits as f64 / expand_total_requests as f64) * 100.0
        } else {
            0.0
        };

        CacheStats {
            entry_count: self.check_cache.entry_count() + self.expand_cache.entry_count(),
            weighted_size: self.check_cache.weighted_size() + self.expand_cache.weighted_size(),
            hits,
            misses,
            hit_rate,
            expand_hits,
            expand_misses,
            expand_hit_rate,
            invalidations: self.invalidations.load(Ordering::Relaxed),
        }
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.expand_hits.store(0, Ordering::Relaxed);
        self.expand_misses.store(0, Ordering::Relaxed);
        self.invalidations.store(0, Ordering::Relaxed);
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
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub expand_hits: u64,
    pub expand_misses: u64,
    pub expand_hit_rate: f64,
    pub invalidations: u64,
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

    #[tokio::test]
    async fn test_cache_hit_miss_tracking() {
        let cache = AuthCache::new(100, Duration::from_secs(60));

        let key1 = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        let key2 = CheckCacheKey {
            subject: "user:bob".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        // First access - miss
        assert!(cache.get_check(&key1).await.is_none());
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate, 0.0);

        // Insert value
        cache.put_check(key1.clone(), Decision::Allow).await;

        // Second access - hit
        assert_eq!(cache.get_check(&key1).await, Some(Decision::Allow));
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate, 50.0);

        // Third access - another hit
        assert_eq!(cache.get_check(&key1).await, Some(Decision::Allow));
        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate - 66.66).abs() < 0.1);

        // Different key - miss
        assert!(cache.get_check(&key2).await.is_none());
        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.hit_rate, 50.0);
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let cache = AuthCache::new(100, Duration::from_secs(60));

        let key = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        cache.put_check(key.clone(), Decision::Allow).await;
        assert_eq!(cache.get_check(&key).await, Some(Decision::Allow));

        // Invalidate
        cache.invalidate_before(Revision(2)).await;

        let stats = cache.stats();
        assert_eq!(stats.invalidations, 1);

        // Cache should be empty
        assert!(cache.get_check(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_invalidate_all() {
        let cache = AuthCache::new(100, Duration::from_secs(60));

        let key1 = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        let key2 = CheckCacheKey {
            subject: "user:bob".to_string(),
            resource: "doc:readme".to_string(),
            permission: "write".to_string(),
            revision: Revision(1),
        };

        cache.put_check(key1.clone(), Decision::Allow).await;
        cache.put_check(key2.clone(), Decision::Deny).await;

        assert_eq!(cache.get_check(&key1).await, Some(Decision::Allow));
        assert_eq!(cache.get_check(&key2).await, Some(Decision::Deny));

        cache.invalidate_all().await;

        assert!(cache.get_check(&key1).await.is_none());
        assert!(cache.get_check(&key2).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let cache = AuthCache::new(100, Duration::from_millis(100));

        let key = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        cache.put_check(key.clone(), Decision::Allow).await;
        assert_eq!(cache.get_check(&key).await, Some(Decision::Allow));

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        assert!(cache.get_check(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_max_capacity() {
        let cache = AuthCache::new(2, Duration::from_secs(60));

        let key1 = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:1".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        let key2 = CheckCacheKey {
            subject: "user:bob".to_string(),
            resource: "doc:2".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        let key3 = CheckCacheKey {
            subject: "user:charlie".to_string(),
            resource: "doc:3".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        cache.put_check(key1.clone(), Decision::Allow).await;
        cache.put_check(key2.clone(), Decision::Allow).await;
        cache.put_check(key3.clone(), Decision::Allow).await;

        // Wait for pending tasks to complete
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cache should have at most 2 entries (LRU eviction)
        let stats = cache.stats();
        assert!(stats.entry_count <= 2);
    }

    #[tokio::test]
    async fn test_cache_stats_reset() {
        let cache = AuthCache::new(100, Duration::from_secs(60));

        let key = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        cache.get_check(&key).await; // miss
        cache.put_check(key.clone(), Decision::Allow).await;
        cache.get_check(&key).await; // hit

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);

        cache.reset_stats();

        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate, 0.0);
    }

    #[tokio::test]
    async fn test_cache_key_construction() {
        let key = CheckCacheKey::new(
            "user:alice".to_string(),
            "doc:readme".to_string(),
            "read".to_string(),
            Revision(42),
        );

        assert_eq!(key.subject, "user:alice");
        assert_eq!(key.resource, "doc:readme");
        assert_eq!(key.permission, "read");
        assert_eq!(key.revision, Revision(42));
    }

    #[tokio::test]
    async fn test_cache_different_revisions() {
        let cache = AuthCache::new(100, Duration::from_secs(60));

        let key_rev1 = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };

        let key_rev2 = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(2),
        };

        cache.put_check(key_rev1.clone(), Decision::Allow).await;
        cache.put_check(key_rev2.clone(), Decision::Deny).await;

        // Both should be independently cached
        assert_eq!(cache.get_check(&key_rev1).await, Some(Decision::Allow));
        assert_eq!(cache.get_check(&key_rev2).await, Some(Decision::Deny));
    }

    #[tokio::test]
    async fn test_expand_cache_operations() {
        let cache = AuthCache::default();

        let key = ExpandCacheKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            revision: Revision(1),
        };

        // Initially empty
        assert!(cache.get_expand(&key).await.is_none());

        // Add users
        let users = vec!["user:alice".to_string(), "user:bob".to_string()];
        cache.put_expand(key.clone(), users.clone()).await;

        // Should be cached
        assert_eq!(cache.get_expand(&key).await, Some(users));

        // Check stats
        let stats = cache.stats();
        assert_eq!(stats.expand_hits, 1);
        assert_eq!(stats.expand_misses, 1);
        assert_eq!(stats.expand_hit_rate, 50.0);
    }

    #[tokio::test]
    async fn test_expand_cache_hit_miss() {
        let cache = AuthCache::default();

        let key1 = ExpandCacheKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            revision: Revision(1),
        };

        let key2 = ExpandCacheKey {
            object: "doc:readme".to_string(),
            relation: "editor".to_string(),
            revision: Revision(1),
        };

        let users1 = vec!["user:alice".to_string()];
        let users2 = vec!["user:bob".to_string()];

        // Populate cache
        cache.put_expand(key1.clone(), users1.clone()).await;
        cache.put_expand(key2.clone(), users2.clone()).await;

        // Hit on key1
        assert_eq!(cache.get_expand(&key1).await, Some(users1));

        // Hit on key2
        assert_eq!(cache.get_expand(&key2).await, Some(users2));

        // Stats should show hits
        let stats = cache.stats();
        assert_eq!(stats.expand_hits, 2);
        assert_eq!(stats.expand_misses, 0);
        assert_eq!(stats.expand_hit_rate, 100.0);
    }

    #[tokio::test]
    async fn test_expand_cache_invalidation() {
        let cache = AuthCache::new(100, Duration::from_secs(60));

        let key = ExpandCacheKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            revision: Revision(1),
        };

        let users = vec!["user:alice".to_string()];
        cache.put_expand(key.clone(), users.clone()).await;
        assert_eq!(cache.get_expand(&key).await, Some(users));

        // Invalidate all
        cache.invalidate_all().await;

        // Should be gone
        assert!(cache.get_expand(&key).await.is_none());

        let stats = cache.stats();
        assert_eq!(stats.invalidations, 1);
    }

    #[tokio::test]
    async fn test_expand_cache_revision_isolation() {
        let cache = AuthCache::default();

        let key_rev1 = ExpandCacheKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            revision: Revision(1),
        };

        let key_rev2 = ExpandCacheKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            revision: Revision(2),
        };

        let users_rev1 = vec!["user:alice".to_string()];
        let users_rev2 = vec!["user:alice".to_string(), "user:bob".to_string()];

        cache.put_expand(key_rev1.clone(), users_rev1.clone()).await;
        cache.put_expand(key_rev2.clone(), users_rev2.clone()).await;

        // Both revisions should be independently cached
        assert_eq!(cache.get_expand(&key_rev1).await, Some(users_rev1));
        assert_eq!(cache.get_expand(&key_rev2).await, Some(users_rev2));
    }

    #[tokio::test]
    async fn test_mixed_cache_stats() {
        let cache = AuthCache::default();

        // Check cache
        let check_key = CheckCacheKey {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "read".to_string(),
            revision: Revision(1),
        };
        cache.put_check(check_key.clone(), Decision::Allow).await;
        let _ = cache.get_check(&check_key).await;

        // Expand cache
        let expand_key = ExpandCacheKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            revision: Revision(1),
        };
        let users = vec!["user:alice".to_string()];
        cache.put_expand(expand_key.clone(), users).await;
        let _ = cache.get_expand(&expand_key).await;

        // Run pending tasks to ensure entries are synced
        cache.check_cache.run_pending_tasks().await;
        cache.expand_cache.run_pending_tasks().await;

        // Both caches should have stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.expand_hits, 1);
        assert_eq!(stats.expand_misses, 0);
        assert_eq!(stats.entry_count, 2); // One check + one expand
    }
}
