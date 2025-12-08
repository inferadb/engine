# Storage Backends

InferaDB provides a flexible storage abstraction layer that allows you to choose different storage backends based on your needs. The storage layer is completely abstracted through the `TupleStore` trait, making it easy to switch between backends without changing application code.

## Overview

The storage layer is responsible for:

- **Persistent tuple storage** - Storing authorization relationship tuples
- **Revision management** - MVCC (Multi-Version Concurrency Control) for consistent reads
- **Indexing** - Efficient lookups by object, relation, and user
- **Transactions** - ACID guarantees for write operations

## Available Backends

### Memory Backend (Default)

**Status**: ✅ Production-ready for testing and development

The in-memory backend stores all data in RAM using Rust's standard collections. It's the default backend and requires no external dependencies.

**Features:**

- Zero configuration required
- Perfect for development and testing
- Fast performance (sub-microsecond latency)
- Full MVCC support with revision isolation
- Garbage collection for old revisions

**Limitations:**

- Data is not persisted to disk
- Limited to single-node deployment
- Memory-bound (suitable for datasets up to ~1M tuples)

**Best for:**

- Local development
- Unit and integration testing
- Small-scale deployments
- Proof-of-concept implementations

See [Memory Backend Documentation](./storage-memory.md) for details.

### FoundationDB Backend (Optional)

**Status**: ✅ Production-ready (requires FDB cluster)

The FoundationDB backend provides distributed, ACID transactions with horizontal scalability and high availability.

**Features:**

- Full ACID transactions across nodes
- Horizontal scalability (petabyte scale)
- High availability with automatic failover
- Point-in-time reads with MVCC
- Sub-5ms p99 latency
- Automatic data replication

**Requirements:**

- FoundationDB cluster (6.3+)
- Compile with `--features fdb`
- FoundationDB client library

**Best for:**

- Production deployments
- Multi-region setups
- Large datasets (millions+ tuples)
- High availability requirements
- Distributed systems

See [FoundationDB Backend Documentation](./storage-foundationdb.md) for details.

## Backend Selection

### Using the Storage Factory

The `StorageFactory` provides a unified interface for creating storage backends:

```rust
use inferadb_engine_store::{StorageFactory, StorageConfig, BackendType};

// Method 1: Use default memory backend
let store = StorageFactory::memory();

// Method 2: Create from configuration
let config = StorageConfig::memory();
let store = StorageFactory::create(config).await?;

// Method 3: Create from string (runtime selection)
let backend = "memory"; // or "foundationdb"
let store = StorageFactory::from_str(backend, None).await?;

// Method 4: FoundationDB with cluster file
#[cfg(feature = "fdb")]
{
    let config = StorageConfig::foundationdb(Some("/etc/foundationdb/fdb.cluster".to_string()));
    let store = StorageFactory::create(config).await?;
}
```

### Configuration File

Configure the storage backend in your `config.toml`:

```toml
[store]
backend = "memory"  # or "foundationdb"
# connection_string = "/etc/foundationdb/fdb.cluster"  # Optional for FDB
```

Load configuration and create store:

```rust
use inferadb_engine_config::Config;
use inferadb_engine_store::StorageFactory;

let config = Config::load("config.toml")?;
let store = StorageFactory::from_str(
    &config.store.backend,
    config.store.connection_string
).await?;
```

### Environment Variables

Override configuration with environment variables:

```bash
# Use memory backend (default)
INFERADB__STORE__BACKEND=memory

# Use FoundationDB backend
INFERADB__STORE__BACKEND=foundationdb
INFERADB__STORE__CONNECTION_STRING=/etc/foundationdb/fdb.cluster
```

## Storage Abstraction

All backends implement the `TupleStore` trait, providing a consistent interface:

```rust
#[async_trait]
pub trait TupleStore: Send + Sync {
    /// Read tuples matching the key at a specific revision
    async fn read(&self, key: &TupleKey, revision: Revision) -> Result<Vec<Tuple>>;

    /// Write tuples and return the new revision
    async fn write(&self, tuples: Vec<Tuple>) -> Result<Revision>;

    /// Get the current revision
    async fn get_revision(&self) -> Result<Revision>;

    /// Delete tuples matching the key
    async fn delete(&self, key: &TupleKey) -> Result<Revision>;
}
```

This abstraction ensures:

- **Backend agnostic code** - Write once, run on any backend
- **Easy testing** - Use memory backend in tests, production backend in deployment
- **Zero-cost abstraction** - No runtime overhead beyond the storage layer

## Choosing a Backend

| Criteria          | Memory             | FoundationDB            |
| ----------------- | ------------------ | ----------------------- |
| Setup complexity  | ✅ None            | ⚠️ Requires FDB cluster |
| Performance       | ✅ Sub-microsecond | ✅ Sub-5ms p99          |
| Scalability       | ❌ Single node     | ✅ Horizontal scaling   |
| Persistence       | ❌ RAM only        | ✅ Durable storage      |
| High availability | ❌ No              | ✅ Yes                  |
| Production ready  | ⚠️ Small scale     | ✅ Yes                  |
| Cost              | ✅ Free            | ⚠️ Infrastructure cost  |

**Quick Decision Guide:**

- **Development/Testing**: Use Memory backend
- **Small production (<10k tuples)**: Memory backend is fine
- **Production (>10k tuples)**: Use FoundationDB backend
- **Multi-region**: Use FoundationDB backend
- **High availability required**: Use FoundationDB backend

## Adding Custom Backends

InferaDB's storage layer is designed to be extensible. To add a new backend:

1. **Implement the `TupleStore` trait**:

```rust
use async_trait::async_trait;
use inferadb_engine_store::{TupleStore, Tuple, TupleKey, Revision, Result};

pub struct MyBackend {
    // Your backend implementation
}

#[async_trait]
impl TupleStore for MyBackend {
    async fn read(&self, key: &TupleKey, revision: Revision) -> Result<Vec<Tuple>> {
        // Implementation
    }

    async fn write(&self, tuples: Vec<Tuple>) -> Result<Revision> {
        // Implementation
    }

    async fn get_revision(&self) -> Result<Revision> {
        // Implementation
    }

    async fn delete(&self, key: &TupleKey) -> Result<Revision> {
        // Implementation
    }
}
```

1. **Add to `BackendType` enum** (in `factory.rs`):

```rust
pub enum BackendType {
    Memory,
    FoundationDB,
    MyBackend,  // Add your backend
}
```

1. **Update `StorageFactory`**:

```rust
impl StorageFactory {
    pub async fn create(config: StorageConfig) -> Result<Arc<dyn TupleStore>> {
        match config.backend {
            BackendType::Memory => { /* ... */ }
            BackendType::FoundationDB => { /* ... */ }
            BackendType::MyBackend => {
                Ok(Arc::new(MyBackend::new()?) as Arc<dyn TupleStore>)
            }
        }
    }
}
```

## Performance Considerations

### Memory Backend

- **Reads**: O(log n) for indexed lookups
- **Writes**: O(log n) for insertion + index updates
- **Space**: O(n × revisions) - grows with data and history

### FoundationDB Backend

- **Reads**: Network latency + FDB key lookup (typically <5ms)
- **Writes**: Network latency + FDB transaction commit (typically <10ms)
- **Space**: Efficient storage with FDB's built-in compaction

### Optimization Tips

1. **Batch Operations**: Write multiple tuples in a single transaction
2. **Revision Management**: Use garbage collection to clean old revisions
3. **Caching**: Enable the cache layer for frequently accessed tuples
4. **Indexing**: Both backends maintain indexes automatically

## Migration Between Backends

To migrate from Memory to FoundationDB (or vice versa):

1. **Export data** from source backend:

```rust
let source = StorageFactory::memory();
let current_rev = source.get_revision().await?;

// Read all tuples
let mut all_tuples = Vec::new();
// (enumerate objects/relations and read)
```

1. **Import data** to target backend:

```rust
let target = StorageFactory::from_str("foundationdb", cluster_file).await?;
target.write(all_tuples).await?;
```

1. **Update configuration** to use new backend

## Troubleshooting

### Memory Backend Issues

**Problem**: Out of memory errors

- **Solution**: Use FoundationDB backend or implement periodic GC

**Problem**: Data lost on restart

- **Solution**: Memory backend is not persistent by design. Use FoundationDB for persistence.

### FoundationDB Backend Issues

**Problem**: Connection errors

- **Solution**: Verify FDB cluster is running and cluster file path is correct

**Problem**: Transaction timeouts

- **Solution**: Check FDB cluster health, increase transaction timeout if needed

**Problem**: Slow performance

- **Solution**: Check FDB cluster capacity, optimize batch sizes, enable caching

## See Also

- [Memory Backend Details](./storage-memory.md)
- [FoundationDB Backend Details](./storage-foundationdb.md)
- [Architecture Overview](./architecture.md)
- [Caching Layer](./caching.md)
- [Revision Tokens](./revision-tokens.md)
