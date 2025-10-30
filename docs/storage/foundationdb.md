# FoundationDB Storage Backend

The FoundationDB backend provides a production-ready, distributed storage layer with ACID transactions, horizontal scalability, and high availability.

## Overview

FoundationDB is a distributed database designed to handle large volumes of structured data across clusters of commodity servers. InferaDB leverages FDB's strengths to provide:

- **ACID Transactions**: Serializable isolation across the entire database
- **Horizontal Scalability**: Scale from single node to hundreds of nodes
- **High Availability**: Automatic failover and self-healing
- **Multi-Version Concurrency Control**: Point-in-time consistent reads
- **Low Latency**: Sub-5ms p99 latency for most operations

## Architecture

### Key Space Organization

InferaDB uses FoundationDB's **subspace** feature to organize data into three logical namespaces:

```
/tuples/<object>/<relation>/<user>/<revision> = "active" | "deleted"
/revisions/current = <current_revision_number>
/indexes/obj/<object>/<relation>/<user>/<revision> = ""
/indexes/user/<user>/<relation>/<object>/<revision> = ""
```

### Subspaces

**1. Tuples Subspace**

- Stores actual tuple data with revision tracking
- Key: `(object, relation, user, revision)`
- Value: `"active"` or `"deleted"` marker
- Enables MVCC by maintaining version history

**2. Revisions Subspace**

- Tracks global revision counter
- Key: `"current"`
- Value: Latest revision number (JSON-encoded u64)
- Atomically incremented in transactions

**3. Indexes Subspace**

- Two index types for efficient queries:
  - **Object index**: Forward lookup (object+relation → users)
  - **User index**: Reverse lookup (user+relation → objects)
- Maintains revision history per index entry

### Data Model

```rust
pub struct FoundationDBBackend {
    db: Arc<Database>,              // FDB database handle
    tuples_subspace: Subspace,      // Tuple storage
    revision_subspace: Subspace,    // Revision tracking
    index_subspace: Subspace,       // Indexes
}
```

## Setup

### Prerequisites

1. **FoundationDB Cluster**

   - Version 6.3 or higher recommended
   - Running fdbserver instances
   - Configured cluster file

2. **FoundationDB Client Library**

   ```bash
   # macOS
   brew install foundationdb

   # Ubuntu/Debian
   wget https://github.com/apple/foundationdb/releases/download/7.1.27/foundationdb-clients_7.1.27-1_amd64.deb
   sudo dpkg -i foundationdb-clients_7.1.27-1_amd64.deb

   # Or build from source
   git clone https://github.com/apple/foundationdb.git
   ```

3. **Rust with FDB Feature**
   ```toml
   # Cargo.toml
   [dependencies]
   infera-store = { version = "0.1", features = ["fdb"] }
   ```

### Compilation

```bash
# Build with FoundationDB support
cargo build --features fdb

# Run tests (requires FDB running)
cargo test --features fdb -- --ignored
```

### Configuration

**Method 1: Default Cluster File**

```rust
let backend = FoundationDBBackend::new().await?;
// Uses /etc/foundationdb/fdb.cluster
```

**Method 2: Custom Cluster File**

```rust
let backend = FoundationDBBackend::with_cluster_file(
    Some("/path/to/fdb.cluster")
).await?;
```

**Method 3: Storage Factory**

```rust
use infera_store::{StorageFactory, StorageConfig};

let config = StorageConfig::foundationdb(
    Some("/etc/foundationdb/fdb.cluster".to_string())
);
let store = StorageFactory::create(config).await?;
```

**Method 4: Configuration File**

```toml
# config.toml
[store]
backend = "foundationdb"
connection_string = "/etc/foundationdb/fdb.cluster"
```

```rust
let config = Config::load("config.toml")?;
let store = StorageFactory::from_str(
    &config.store.backend,
    config.store.connection_string
).await?;
```

## Operations

### Read Operation

**Transaction Flow:**

1. Begin FDB transaction
2. Query index subspace for matching keys (range read)
3. Filter by revision (≤ requested revision)
4. Deduplicate (keep only latest version per tuple)
5. Verify tuple is active (not deleted)
6. Return tuples

**Example:**

```rust
let key = TupleKey {
    object: "doc:readme".to_string(),
    relation: "reader".to_string(),
    user: None,  // All users
};

let revision = store.get_revision().await?;
let tuples = store.read(&key, revision).await?;
```

**Performance:**

- Latency: 1-5ms (depends on cluster size and network)
- Throughput: 10K-100K reads/sec per node
- Scales horizontally with cluster size

### Write Operation

**Transaction Flow:**

1. Begin FDB transaction
2. Read and increment global revision counter
3. For each tuple:
   - Write tuple data to tuples subspace
   - Update object index
   - Update user index
4. Commit transaction (automatic retries on conflict)

**Example:**

```rust
let tuples = vec![
    Tuple {
        object: "doc:readme".to_string(),
        relation: "reader".to_string(),
        user: "alice".to_string(),
    },
    Tuple {
        object: "doc:readme".to_string(),
        relation: "editor".to_string(),
        user: "bob".to_string(),
    },
];

let revision = store.write(tuples).await?;
```

**Atomicity:**

- All tuples in a batch written at same revision
- Either all succeed or all fail
- FDB handles automatic retries on conflicts

**Performance:**

- Latency: 5-10ms (includes commit time)
- Throughput: 10K-50K writes/sec per cluster
- Batch writes are more efficient

### Delete Operation

**Transaction Flow:**

1. Begin FDB transaction
2. Increment global revision
3. Find all matching tuples (by object+relation or specific user)
4. Write deletion markers at new revision
5. Commit transaction

**Example:**

```rust
// Delete all readers
let key = TupleKey {
    object: "doc:readme".to_string(),
    relation: "reader".to_string(),
    user: None,
};
store.delete(&key).await?;

// Delete specific user
let key = TupleKey {
    object: "doc:readme".to_string(),
    relation: "reader".to_string(),
    user: Some("alice".to_string()),
};
store.delete(&key).await?;
```

**Soft Deletes:**

- Deletes are markers, not physical removals
- Enables MVCC (read old versions)
- FDB's compaction cleans up old data automatically

## Features

### ACID Transactions

FoundationDB provides full ACID guarantees:

```rust
// All operations are transactional
let rev1 = store.write(batch1).await?;  // Atomic
let rev2 = store.write(batch2).await?;  // Atomic

// Reads see consistent snapshot
let tuples = store.read(&key, rev1).await?;  // Sees state at rev1
```

**Isolation Levels:**

- Serializable isolation by default
- Snapshot reads at any revision
- No read-write conflicts (MVCC)

### Revision Management

**Global Revision Counter:**

- Monotonically increasing
- Atomically incremented per transaction
- Enables point-in-time queries

**Revision History:**

- Each tuple stores all versions with revisions
- Read at any past revision
- Automatic cleanup via FDB compaction

**Example:**

```rust
// Write at revision 1
let rev1 = store.write(tuples_v1).await?;

// Write at revision 2
let rev2 = store.write(tuples_v2).await?;

// Read historical data
let data_at_rev1 = store.read(&key, rev1).await?;
let data_at_rev2 = store.read(&key, rev2).await?;
```

### Horizontal Scalability

**Scale Out:**

- Add more fdbserver processes to increase capacity
- Data automatically redistributes
- No application changes needed

**Performance Scaling:**

```
1 node:   10K ops/sec
3 nodes:  30K ops/sec
10 nodes: 100K ops/sec
50 nodes: 500K ops/sec
```

**Storage Scaling:**

- FDB handles petabyte-scale data
- Automatic sharding and rebalancing
- No manual partitioning required

### High Availability

**Replication:**

- Configurable replication factor (default: 3)
- Data replicated across failure domains
- Synchronous replication for consistency

**Automatic Failover:**

- Node failures detected in seconds
- Automatic promotion of replicas
- No data loss on single node failure

**Recovery:**

```
Node failure:     < 5 seconds to recover
Data center loss: < 60 seconds (with multi-DC setup)
Full cluster loss: Requires backup restore
```

## Performance Tuning

### Batch Operations

```rust
// Good: Single transaction for 100 tuples
let tuples = vec![/* 100 tuples */];
store.write(tuples).await?;

// Bad: 100 separate transactions
for tuple in tuples {
    store.write(vec![tuple]).await?;  // Very slow!
}
```

**Benchmarks:**

```
Single writes: 10ms per write, 100 writes/sec
Batch (100):   50ms per batch, 2000 writes/sec (20x faster)
```

### Read Optimization

**Use Range Reads:**

```rust
// Efficient: Single range read from index
let key = TupleKey {
    object: "doc:readme".to_string(),
    relation: "reader".to_string(),
    user: None,  // Gets all users in one read
};
store.read(&key, revision).await?;
```

**Caching:**

```rust
// Enable InferaDB's cache layer
let cache = AuthCache::new(10_000, Duration::from_secs(300));
// Cache sits in front of FDB, reducing read load
```

### Transaction Sizes

**Limits:**

- Max transaction size: 10MB
- Max keys per transaction: ~100K
- Max transaction duration: 5 seconds

**Best Practices:**

- Keep transactions small (<1MB)
- Batch operations when possible
- Split very large writes across multiple transactions

### Cluster Configuration

**Storage Engine:**

```bash
# SSDs recommended for best performance
fdbcli> configure ssd
```

**Replication:**

```bash
# Triple replication (default, recommended)
fdbcli> configure triple

# Double replication (for development)
fdbcli> configure double
```

**Region Setup:**

```bash
# Multi-region for disaster recovery
fdbcli> configure regions
```

## Monitoring

### Key Metrics

**Latency:**

```rust
use std::time::Instant;

let start = Instant::now();
let result = store.read(&key, revision).await?;
let latency = start.elapsed();

println!("Read latency: {:?}", latency);
```

**Throughput:**

```bash
# Use fdbcli to monitor cluster
fdbcli> status details

# Key metrics:
# - Transactions/sec
# - Reads/sec
# - Writes/sec
# - Storage used
```

**FDB Status:**

```bash
fdbcli> status

# Check:
# - Cluster healthy?
# - All processes running?
# - Replication factor met?
# - Storage capacity?
```

### Alerting

**Critical Alerts:**

- Transaction timeouts > 100ms
- Replication factor below target
- Storage capacity > 80%
- Process failures

**Warning Alerts:**

- Latency p99 > 10ms
- Storage capacity > 60%
- Network saturation

## Backup and Recovery

### Continuous Backup

```bash
# Start continuous backup
fdbbackup start -d file:///backups/inferadb \
  -w --snapshotInterval 864000

# Monitor backup status
fdbbackup status
```

### Point-in-Time Recovery

```bash
# Restore from backup at specific timestamp
fdbrestore start -r file:///backups/inferadb \
  --timestamp 2024-01-15-12:00:00

# Verify restore
fdbrestore status
```

### Disaster Recovery

**Multi-Region Setup:**

1. Deploy FDB cluster across regions
2. Configure region-aware replication
3. Set up cross-region backup
4. Test failover procedures

## Limitations and Considerations

### 1. Transaction Size Limits

**Issue:** Max 10MB per transaction

**Workaround:**

```rust
// Split large batches
for chunk in tuples.chunks(1000) {
    store.write(chunk.to_vec()).await?;
}
```

### 2. Key Size Limits

**Issue:** Max 10KB per key

**Workaround:**

- Keep object/relation/user names reasonably sized
- Use IDs instead of long strings
- InferaDB's design stays well within limits

### 3. Operational Complexity

**Issue:** Requires FDB cluster setup and maintenance

**Mitigation:**

- Use managed FDB service if available
- Follow FDB operational best practices
- Start with 3-node cluster for simplicity

### 4. Network Latency

**Issue:** Each operation involves network round-trip

**Mitigation:**

- Deploy InferaDB close to FDB cluster
- Use same data center/region
- Enable caching layer

## Troubleshooting

### Connection Issues

**Symptom:** "Failed to initialize FDB" error

**Solutions:**

1. Verify FDB cluster is running:

   ```bash
   fdbcli> status
   ```

2. Check cluster file exists:

   ```bash
   ls -la /etc/foundationdb/fdb.cluster
   ```

3. Verify client can connect:
   ```bash
   fdbcli> status
   ```

### Transaction Timeouts

**Symptom:** "Transaction exceeded 5 second time limit"

**Solutions:**

1. Reduce transaction size
2. Check FDB cluster health
3. Increase timeout (not recommended):
   ```rust
   // Requires custom transaction handling
   ```

### Performance Issues

**Symptom:** High latency (>20ms)

**Solutions:**

1. Check FDB cluster status
2. Verify network latency to FDB
3. Enable caching
4. Review transaction sizes
5. Check for hot keys

## Migration

### From Memory to FoundationDB

```rust
// 1. Create both backends
let memory = MemoryBackend::new();
let fdb = FoundationDBBackend::new().await?;

// 2. Get current state from memory
let mem_revision = memory.get_revision().await?;

// 3. Enumerate all tuples (application-specific)
let all_tuples = /* collect all tuples from memory */;

// 4. Write to FDB
fdb.write(all_tuples).await?;

// 5. Verify migration
let fdb_revision = fdb.get_revision().await?;
assert_eq!(fdb_revision.0, 1);  // First write
```

### From FoundationDB to Different FDB Cluster

```bash
# Use FDB backup/restore
fdbbackup start -d file:///migration
fdbrestore start -r file:///migration --destcluster new.cluster
```

## Best Practices

### 1. Connection Pooling

```rust
// Reuse database handle (already Arc<Database>)
let store = FoundationDBBackend::new().await?;
// Pass store around as Arc<dyn TupleStore>
```

### 2. Error Handling

```rust
match store.write(tuples).await {
    Ok(rev) => println!("Wrote at revision {:?}", rev),
    Err(StoreError::Database(e)) => {
        eprintln!("FDB error: {}", e);
        // Retry logic, alerting, etc.
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

### 3. Monitoring

```rust
// Add metrics collection
let start = Instant::now();
let result = store.read(&key, revision).await?;
metrics::histogram!("fdb_read_duration").record(start.elapsed());
```

### 4. Graceful Degradation

```rust
// Fallback to cache on FDB errors
match store.read(&key, revision).await {
    Ok(tuples) => tuples,
    Err(_) => {
        // Try cache
        cache.get(&key).unwrap_or_default()
    }
}
```

## See Also

- [Storage Backends Overview](./storage-backends.md)
- [Memory Backend](./storage-memory.md)
- [FoundationDB Documentation](https://apple.github.io/foundationdb/)
- [FDB Best Practices](https://apple.github.io/foundationdb/best-practices.html)
- [Revision Tokens](./revision-tokens.md)
