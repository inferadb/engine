# Memory Storage Backend

The Memory backend is InferaDB's default storage implementation, providing a fast, zero-configuration storage layer ideal for development and testing.

## Overview

The Memory backend stores all authorization tuples in RAM using Rust's standard collections. It provides full MVCC (Multi-Version Concurrency Control) support with revision-based isolation, making it functionally equivalent to production backends but without persistence.

## Architecture

### Data Structures

```rust
pub struct MemoryBackend {
    // Main tuple storage: (object, relation, user) -> [revisions]
    tuples: RwLock<HashMap<TupleKey, Vec<TupleVersion>>>,

    // Index for reverse lookups: (user, relation) -> [objects]
    user_index: RwLock<HashMap<(String, String), BTreeMap<String, Vec<Revision>>>>,

    // Global revision counter
    current_revision: AtomicU64,
}
```

### Key Components

1. **Tuple Storage**
    - HashMap for O(1) lookup by (object, relation, user)
    - Each key stores a vector of versions (MVCC)
    - Versions are ordered by revision

2. **User Index**
    - Enables reverse lookups (find all objects for a user+relation)
    - BTreeMap for ordered iteration
    - Maintains revision history per entry

3. **Revision Counter**
    - Atomic U64 for thread-safe increment
    - Monotonically increasing
    - Never resets (unless GC removes history)

## Features

### Multi-Version Concurrency Control (MVCC)

Each tuple stores multiple versions with revision timestamps:

```rust
struct TupleVersion {
    revision: Revision,
    tuple: Tuple,
    deleted: bool,
}
```

**Benefits:**

- Point-in-time reads without blocking writes
- No read/write contention
- Isolation between transactions

**Example:**

```rust
// Write at revision 1
store.write(vec![Tuple { object: "doc:1", relation: "reader", user: "alice" }]).await?;

// Write at revision 2 (overwrite)
store.write(vec![Tuple { object: "doc:1", relation: "reader", user: "bob" }]).await?;

// Can still read at revision 1
let key = TupleKey { object: "doc:1", relation: "reader", user: None };
let tuples_at_rev1 = store.read(&key, Revision(1)).await?;  // Returns alice
let tuples_at_rev2 = store.read(&key, Revision(2)).await?;  // Returns bob
```

### Duplicate Prevention

The Memory backend automatically prevents duplicate tuples:

```rust
// First write
store.write(vec![tuple.clone()]).await?;  // Revision 1

// Second write of same tuple
store.write(vec![tuple.clone()]).await?;  // Still revision 1 (deduped)
```

### Garbage Collection

Remove old revisions to free memory:

```rust
let store = MemoryBackend::new();

// Create some history
store.write(tuples_v1).await?;  // Rev 1
store.write(tuples_v2).await?;  // Rev 2
store.write(tuples_v3).await?;  // Rev 3

// Remove versions before revision 2
store.gc_before(Revision(2)).await?;

// Rev 1 is gone, but Rev 2 and 3 remain
```

## Operations

### Read

**Signature:**

```rust
async fn read(&self, key: &TupleKey, revision: Revision) -> Result<Vec<Tuple>>
```

**Behavior:**

1. Looks up tuples by (object, relation)
2. Filters by user if specified in key
3. Returns only tuples at or before the requested revision
4. Excludes deleted tuples

**Time Complexity:** O(log n) for lookup + O(m) for filtering
where n = total tuples, m = matching tuples

**Example:**

```rust
let key = TupleKey {
    object: "doc:readme".to_string(),
    relation: "reader".to_string(),
    user: Some("alice".to_string()),  // Filter by specific user
};

let tuples = store.read(&key, current_revision).await?;
```

### Write

**Signature:**

```rust
async fn write(&self, tuples: Vec<Tuple>) -> Result<Revision>
```

**Behavior:**

1. Atomically increments global revision
2. For each tuple:
    - Checks for duplicates
    - Adds new version at current revision
    - Updates user index
3. Returns the new revision

**Time Complexity:** O(n × log m)
where n = tuples written, m = existing versions per tuple

**Example:**

```rust
let tuples = vec![
    Tuple { object: "doc:1", relation: "reader", user: "alice" },
    Tuple { object: "doc:1", relation: "editor", user: "bob" },
];

let revision = store.write(tuples).await?;
```

### Delete

**Signature:**

```rust
async fn delete(&self, key: &TupleKey) -> Result<Revision>
```

**Behavior:**

1. Atomically increments global revision
2. Marks matching tuples as deleted at new revision
3. Preserves history (soft delete)
4. Updates indexes

**Time Complexity:** O(log n + m)
where n = total tuples, m = matching tuples

**Example:**

```rust
// Delete all readers for doc:1
let key = TupleKey {
    object: "doc:1".to_string(),
    relation: "reader".to_string(),
    user: None,  // Deletes all users
};

store.delete(&key).await?;

// Delete specific user
let key = TupleKey {
    object: "doc:1".to_string(),
    relation: "reader".to_string(),
    user: Some("alice".to_string()),
};

store.delete(&key).await?;
```

### Query Patterns

**Object + Relation Query:**

```rust
// Find all users who can read doc:1
let key = TupleKey {
    object: "doc:1".to_string(),
    relation: "reader".to_string(),
    user: None,
};
let readers = store.read(&key, revision).await?;
```

**User + Relation Query (Reverse Lookup):**

```rust
// Find all documents alice can read
let results = store.query_by_user("alice", "reader", revision).await?;
```

**Wildcard Expansion:**

```rust
// Get all relationships for an object
let all_rels = store.query_by_object("doc:1", revision).await?;
```

## Performance Characteristics

### Throughput

| Operation         | Latency | Throughput     |
| ----------------- | ------- | -------------- |
| Single read       | < 1μs   | 1M+ ops/sec    |
| Single write      | < 10μs  | 100K+ ops/sec  |
| Batch write (100) | < 100μs | 1M+ tuples/sec |
| Delete            | < 10μs  | 100K+ ops/sec  |

_Benchmarks on Apple M1, single thread_

### Memory Usage

```
Base overhead: ~1KB per unique (object, relation, user)
Per version: ~200 bytes
Index overhead: ~100 bytes per tuple
```

**Example:**

- 10,000 tuples with 10 versions each
- Memory usage: ~200MB
- With GC (keep 2 versions): ~20MB

### Concurrency

- **Thread-safe**: Uses RwLock for safe concurrent access
- **Read scaling**: Multiple readers can access simultaneously
- **Write contention**: Single writer at a time (per lock)
- **Lock-free reads at known revision**: No locking needed for immutable snapshots

## Testing Support

The Memory backend is perfect for testing:

```rust
#[tokio::test]
async fn test_authorization_check() {
    let store = Arc::new(MemoryBackend::new());

    // Setup test data
    store.write(vec![
        Tuple { object: "doc:1", relation: "owner", user: "alice" },
        Tuple { object: "doc:1", relation: "reader", user: "bob" },
    ]).await.unwrap();

    // Test reads
    let revision = store.get_revision().await.unwrap();
    let key = TupleKey {
        object: "doc:1".to_string(),
        relation: "owner".to_string(),
        user: Some("alice".to_string()),
    };
    let result = store.read(&key, revision).await.unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].user, "alice");
}
```

### Property-Based Testing

The Memory backend includes comprehensive property-based tests using proptest:

```rust
proptest! {
    #[test]
    fn prop_write_then_read_succeeds(tuples in vec(tuple_strategy(), 1..50)) {
        // Test that any written tuple can be read back
    }

    #[test]
    fn prop_revision_increases_monotonically(
        batch1 in vec(tuple_strategy(), 1..10),
        batch2 in vec(tuple_strategy(), 1..10)
    ) {
        // Test that revisions always increase
    }
}
```

## Limitations

### 1. No Persistence

**Issue:** Data is lost on process restart

**Workaround:**

- Use FoundationDB backend for production
- Implement export/import if needed
- Use for development/testing only

### 2. Memory Bounded

**Issue:** Dataset limited by available RAM

**Guideline:**

- Suitable for up to ~1M tuples
- With GC: can handle more with older history removed
- Monitor memory usage in production

**Workaround:**

- Aggressive GC policy
- Migrate to FoundationDB for large datasets

### 3. Single Node

**Issue:** No distribution or replication

**Workaround:**

- Use FoundationDB for multi-node setups
- Memory backend is development/testing only

### 4. No Durable Transactions

**Issue:** Writes are not persisted to disk

**Workaround:**

- Use FoundationDB for durability
- Memory backend has atomic in-memory operations

## Best Practices

### 1. Regular Garbage Collection

```rust
// Keep only last 10 revisions
let current = store.get_revision().await?;
if current.0 > 10 {
    store.gc_before(Revision(current.0 - 10)).await?;
}
```

### 2. Batch Writes

```rust
// Good: Single transaction
let tuples = vec![tuple1, tuple2, tuple3];
store.write(tuples).await?;

// Bad: Multiple transactions
store.write(vec![tuple1]).await?;
store.write(vec![tuple2]).await?;
store.write(vec![tuple3]).await?;
```

### 3. Use Indexes

```rust
// Efficient: Uses index
let results = store.query_by_object("doc:1", revision).await?;

// Less efficient: Would need to scan all tuples
// (Not exposed in API, but internally avoided)
```

### 4. Monitor Memory

```rust
let stats = store.stats().await;
println!("Active tuples: {}", stats.active_tuples);
println!("Total versions: {}", stats.total_versions);
println!("Memory estimate: {}MB", stats.memory_estimate_mb());
```

## Comparison with FoundationDB

| Feature      | Memory            | FoundationDB     |
| ------------ | ----------------- | ---------------- |
| Setup        | Zero config       | Requires cluster |
| Latency      | < 1μs             | < 5ms            |
| Throughput   | 1M+ ops/sec       | 100K+ ops/sec    |
| Persistence  | ❌ No             | ✅ Yes           |
| Distribution | ❌ Single node    | ✅ Multi-node    |
| MVCC         | ✅ Yes            | ✅ Yes           |
| ACID         | ⚠️ In-memory only | ✅ Yes           |
| Max dataset  | ~1M tuples        | Petabytes        |
| Use case     | Dev/test          | Production       |

## See Also

- [Storage Backends Overview](./storage-backends.md)
- [FoundationDB Backend](./storage-foundationdb.md)
- [Revision Tokens](./revision-tokens.md)
- [Caching Layer](./caching.md)
