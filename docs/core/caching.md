# Caching System

InferaDB includes an intelligent caching layer that dramatically improves authorization check performance by caching evaluation results.

## Overview

The caching system uses:

-   **LRU eviction** with time-based expiration (Moka async cache)
-   **Revision-based keys** for correctness guarantees
-   **Automatic invalidation** on writes
-   **Hit/miss tracking** for observability

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Policy Evaluator                    │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │  1. Check cache                          │   │
│  │     └─> Cache hit? Return cached result  │   │
│  │                                          │   │
│  │  2. Cache miss? Evaluate policy          │   │
│  │     └─> Traverse graph, evaluate rules   │   │
│  │                                          │   │
│  │  3. Store result in cache                │   │
│  │     └─> With current revision            │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Cache Key Design

### Structure

```rust
pub struct CheckCacheKey {
    pub subject: String,
    pub resource: String,
    pub permission: String,
    pub revision: u64,
}
```

### Why Include Revision?

Including the revision number in the cache key ensures correctness:

```rust
// At revision 1: user:alice is NOT a viewer
check("user:alice", "doc:1", "viewer") -> DENY (cached at rev 1)

// Write: grant viewer to alice (revision becomes 2)
write([Tuple { object: "doc:1", relation: "viewer", user: "user:alice" }])

// At revision 2: cache key is different, so cache miss
check("user:alice", "doc:1", "viewer") -> ALLOW (cached at rev 2)

// Old cache entry (rev 1) is now stale but harmless
```

## Cache Configuration

### Default Settings

```rust
pub struct CacheConfig {
    pub max_capacity: u64,      // 10,000 entries
    pub ttl_seconds: u64,        // 300 seconds (5 minutes)
    pub tti_seconds: u64,        // 60 seconds (1 minute)
}
```

### Configuration Options

**Max Capacity** - Maximum number of entries before eviction:

```rust
AuthCache::with_capacity(100_000)  // 100k entries
```

**TTL (Time To Live)** - Entry expires after this duration:

```rust
AuthCache::with_ttl(Duration::from_secs(600))  // 10 minutes
```

**TTI (Time To Idle)** - Entry expires if not accessed:

```rust
AuthCache::with_tti(Duration::from_secs(120))  // 2 minutes
```

## Usage

### Basic Usage

```rust
use infera_cache::AuthCache;
use std::sync::Arc;

// Create cache
let cache = Arc::new(AuthCache::default());

// Create evaluator with cache
let evaluator = Evaluator::new_with_cache(
    store,
    schema,
    wasm_host,
    Some(cache.clone())
);

// Checks automatically use cache
let decision = evaluator.check(request).await?;
```

### Manual Cache Operations

```rust
// Check cache directly
let key = CheckCacheKey::new(
    "user:alice".to_string(),
    "document:readme".to_string(),
    "can_view".to_string(),
    revision,
);

if let Some(cached_decision) = cache.get_check(&key).await {
    // Cache hit
    return Ok(cached_decision);
}

// Cache miss - evaluate and store
let decision = evaluate_policy(...).await?;
cache.put_check(key, decision).await;
```

### Cache Statistics

```rust
let stats = cache.stats();
println!("Entries: {}", stats.entry_count);
println!("Size: {} bytes", stats.weighted_size);
println!("Hits: {}", stats.hits);
println!("Misses: {}", stats.misses);
println!("Hit rate: {:.2}%", stats.hit_rate);
println!("Invalidations: {}", stats.invalidations);
```

## Cache Invalidation

### Automatic Invalidation

Cache entries are automatically invalidated on writes:

```rust
// Write new tuples
let new_revision = store.write(tuples).await?;

// All cache entries with old revisions are now stale
// Next check will compute new cache key with new_revision
```

### Manual Invalidation

Invalidate all entries:

```rust
cache.invalidate_all().await;
```

Invalidate entries for specific resources only (selective invalidation):

```rust
// Extract affected resources from tuples
let resources = AuthCache::extract_affected_resources(&tuples);

// Only invalidate cache entries for those resources
cache.invalidate_resources(&resources).await;
```

Invalidate all entries before a specific revision (backward compatibility):

```rust
cache.invalidate_before(revision).await;
```

### Invalidation Strategies

**Revision-based (Default)**:

-   Cache keys include revision number
-   Old entries become unreachable automatically
-   Memory is reclaimed by LRU eviction

**Selective invalidation (Recommended)**:

-   Only invalidates entries for modified resources
-   Uses secondary index to track resource -> cache key mappings
-   More efficient than invalidating all entries
-   Maintains high hit rates during writes

**Eager invalidation (Optional)**:

-   Call `invalidate_all()` after writes
-   Frees memory immediately
-   May cause cache thrashing under high write load

### How Selective Invalidation Works

The cache maintains a secondary index that maps resources to cache keys:

```rust
// When caching a check result
cache.put_check(key, decision).await;
// Internally: resource_index["doc:readme"] = {key1, key2, ...}

// When writing tuples
let tuples = vec![
    Tuple { object: "doc:readme", relation: "viewer", user: "user:alice" }
];
let resources = AuthCache::extract_affected_resources(&tuples);
// resources = ["doc:readme"]

cache.invalidate_resources(&resources).await;
// Only invalidates cache entries for "doc:readme"
// Other entries remain cached
```

This is significantly more efficient than invalidating all entries, especially when:

-   You have a large cache
-   Writes affect only a small subset of resources
-   You want to maintain high hit rates during write operations

## Performance Characteristics

### Latency

| Operation          | Latency |
| ------------------ | ------- |
| Cache hit          | <100μs  |
| Cache miss + store | <1ms    |
| Cache write        | <50μs   |

### Hit Rates

Typical hit rates depend on workload:

| Workload    | Expected Hit Rate |
| ----------- | ----------------- |
| Read-heavy  | >90%              |
| Mixed       | 70-80%            |
| Write-heavy | 50-70%            |

### Memory Usage

Memory per cached entry:

```
Entry size ≈ sizeof(CheckCacheKey) + sizeof(Decision) + overhead
          ≈ (50-100 bytes) + 1 byte + ~50 bytes
          ≈ 100-150 bytes per entry

10,000 entries ≈ 1-1.5 MB
100,000 entries ≈ 10-15 MB
1,000,000 entries ≈ 100-150 MB
```

## Monitoring

### Metrics

The cache exposes metrics via `stats()`:

```rust
pub struct CacheStats {
    pub entry_count: u64,        // Current number of entries
    pub weighted_size: u64,      // Total memory used (bytes)
    pub hits: u64,               // Cache hits
    pub misses: u64,             // Cache misses
    pub hit_rate: f64,           // Hit rate percentage
    pub invalidations: u64,      // Number of invalidations
}
```

### Observability Integration

```rust
// Export metrics to Prometheus
let stats = cache.stats();
metrics::gauge!("cache_entries", stats.entry_count as f64);
metrics::gauge!("cache_size_bytes", stats.weighted_size as f64);
metrics::counter!("cache_hits", stats.hits);
metrics::counter!("cache_misses", stats.misses);
metrics::gauge!("cache_hit_rate", stats.hit_rate);
```

### Alerting

Set up alerts for:

**Low hit rate**: `cache_hit_rate < 50%`

-   May indicate cache is too small
-   Or workload has changed

**High memory usage**: `cache_size_bytes > threshold`

-   Reduce max_capacity
-   Decrease TTL

**High miss rate**: `cache_misses > threshold`

-   Cache warming may be needed
-   Consider increasing capacity

## Optimization Strategies

### 1. Cache Warming

Pre-populate cache with common checks:

```rust
async fn warm_cache(
    cache: Arc<AuthCache>,
    evaluator: Arc<Evaluator>,
    common_checks: Vec<CheckRequest>,
) {
    for request in common_checks {
        // This will populate the cache
        let _ = evaluator.check(request).await;
    }
}
```

### 2. Tiered Caching

Use multiple cache layers:

```rust
// L1: In-process cache (Moka)
let l1_cache = AuthCache::with_capacity(10_000);

// L2: Distributed cache (Redis, not yet implemented)
// let l2_cache = RedisCache::new(...);

// Check L1, fallback to L2, fallback to evaluation
```

### 3. Probabilistic Eviction

Extend TTL for frequently accessed entries:

```rust
impl AuthCache {
    pub async fn get_check_with_refresh(&self, key: &CheckCacheKey) -> Option<Decision> {
        if let Some(decision) = self.check_cache.get(key).await {
            // Refresh TTL on access
            self.check_cache.insert(key.clone(), decision).await;
            Some(decision)
        } else {
            None
        }
    }
}
```

### 4. Partitioned Caching

Partition cache by tenant or resource type:

```rust
struct PartitionedCache {
    caches: HashMap<String, AuthCache>,
}

impl PartitionedCache {
    fn get_cache_for_resource(&self, resource: &str) -> &AuthCache {
        let partition = extract_partition(resource);
        self.caches.get(partition).unwrap()
    }
}
```

## Best Practices

### 1. Monitor Cache Effectiveness

Regularly check hit rates:

```rust
let stats = cache.stats();
if stats.hit_rate < 0.5 {
    warn!("Low cache hit rate: {:.2}%", stats.hit_rate * 100.0);
}
```

### 2. Tune TTL Based on Workload

**Short TTL** (30-60s):

-   High write rate
-   Strong consistency requirements
-   Lower memory usage

**Long TTL** (5-10m):

-   Read-heavy workload
-   Eventual consistency acceptable
-   Better hit rates

### 3. Use Revision-Based Keys

Always include revision in cache key:

```rust
// Good: Includes revision
let key = CheckCacheKey::new(subject, resource, permission, current_revision);

// Bad: No revision (may return stale data)
let key = CheckCacheKey::new(subject, resource, permission, 0);
```

### 4. Avoid Cache Stampede

Prevent simultaneous cache misses for same key:

```rust
// Use async lock or similar
let key = compute_cache_key(...);
let mut guard = cache_locks.get(&key).lock().await;

if let Some(cached) = cache.get(&key).await {
    return cached;
}

let result = evaluate(...).await?;
cache.put(&key, result).await;
result
```

### 5. Size the Cache Appropriately

Rule of thumb:

-   1% of total tuple count for typical workloads
-   10% for read-heavy workloads
-   Monitor memory usage and adjust

## Troubleshooting

### Low Hit Rate

**Symptoms**: `hit_rate < 50%`

**Causes**:

1. Cache too small (entries evicted too quickly)
2. High write rate (many revisions)
3. Queries not repeating
4. TTL too short

**Solutions**:

-   Increase `max_capacity`
-   Increase `ttl_seconds`
-   Analyze query patterns
-   Consider cache warming

### High Memory Usage

**Symptoms**: Cache using too much memory

**Causes**:

1. `max_capacity` too high
2. TTL too long
3. Large cache keys (long strings)

**Solutions**:

-   Reduce `max_capacity`
-   Reduce `ttl_seconds`
-   Implement cache entry size limits
-   Use shorter identifiers

### Stale Data

**Symptoms**: Checks returning incorrect results

**Causes**:

1. Not including revision in cache key
2. Clock skew between nodes
3. Cache not invalidated after writes

**Solutions**:

-   Always use revision-based keys
-   Synchronize clocks (NTP)
-   Call `invalidate_all()` after writes in critical paths

### Cache Thrashing

**Symptoms**: High miss rate despite sufficient capacity

**Causes**:

1. Frequent invalidations
2. Working set larger than cache
3. Poor cache key distribution

**Solutions**:

-   Increase cache size
-   Review invalidation strategy
-   Partition cache by tenant/resource
-   Analyze access patterns

## Advanced Features

### Conditional Caching

Only cache certain types of checks:

```rust
impl Evaluator {
    async fn check_with_conditional_cache(&self, request: CheckRequest) -> Result<Decision> {
        // Only cache simple permissions
        let cacheable = is_simple_permission(&request.permission);

        if cacheable {
            // Use cache
            return self.check(request).await;
        } else {
            // Skip cache
            return self.evaluate_without_cache(request).await;
        }
    }
}
```

### Cache Preloading

Load cache from persistent storage on startup:

```rust
async fn preload_cache(cache: Arc<AuthCache>, store: Arc<dyn TupleStore>) {
    // Load most common checks from last session
    let common_checks = load_common_checks().await?;

    for (key, decision) in common_checks {
        cache.put_check(key, decision).await;
    }
}
```

### A/B Testing Cache Strategies

Compare different cache configurations:

```rust
let control_cache = AuthCache::with_ttl(Duration::from_secs(300));
let experiment_cache = AuthCache::with_ttl(Duration::from_secs(600));

// Route 10% of traffic to experiment
let cache = if rand::random::<f64>() < 0.1 {
    &experiment_cache
} else {
    &control_cache
};
```

## Future Enhancements

### Planned Features

1. **Distributed caching** with Redis/Memcached
2. **Negative caching** (cache deny decisions)
3. **Partial result caching** (cache intermediate graph traversals)
4. **Cache warming from access logs**
5. **Adaptive TTL** based on access patterns
6. **Cache compression** for large entries
7. **Cache sharing** across instances

## References

-   [Moka Cache Documentation](https://github.com/moka-rs/moka)
-   [Caching Strategies](https://aws.amazon.com/caching/best-practices/)
-   [Cache Invalidation](https://martinfowler.com/bliki/TwoHardThings.html)
