# Storage Backends

InferaDB provides a flexible storage abstraction layer that allows you to choose different storage backends based on your needs. The storage layer is completely abstracted through the `StorageBackend` trait, making it easy to switch between backends without changing application code.

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

See [Memory Backend Documentation](./memory.md) for details.

### Ledger Backend (Production)

**Status**: ✅ Production-ready

The Ledger backend provides distributed, cryptographically verifiable storage with Raft consensus for strong consistency guarantees.

**Features:**

- Full ACID transactions across nodes
- Horizontal scalability
- High availability with automatic failover
- Cryptographic audit trails (blockchain-based)
- Sub-5ms p99 latency
- Automatic data replication
- WatchBlocks API for real-time cache invalidation

**Requirements:**

- Ledger cluster (StatefulSet in Kubernetes)
- Compile with `--features ledger`

**Best for:**

- Production deployments
- Multi-region setups
- Large datasets (millions+ tuples)
- High availability requirements
- Distributed systems
- Compliance scenarios requiring audit trails

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
let backend = "memory"; // or "ledger"
let store = StorageFactory::from_str(backend, None).await?;

// Method 4: Ledger with endpoint configuration
#[cfg(feature = "ledger")]
{
    let config = StorageConfig::ledger(LedgerConfig {
        endpoint: "http://ledger.inferadb:50051".to_string(),
        client_id: "engine-001".to_string(),
        namespace_id: 1,
        vault_id: Some(1),
    });
    let store = StorageFactory::create(config).await?;
}
```

### Configuration File

Configure the storage backend in your `config.yaml`:

```yaml
engine:
  storage: "memory"  # or "ledger"

  # Ledger configuration (when storage: "ledger")
  ledger:
    endpoint: "http://ledger.inferadb:50051"
    client_id: "engine-prod-001"
    namespace_id: 1
    vault_id: 1  # optional
```

Load configuration and create store:

```rust
use inferadb_engine_config::Config;
use inferadb_engine_store::StorageFactory;

let config = Config::load("config.yaml")?;
let store = StorageFactory::from_config(&config).await?;
```

### Environment Variables

Override configuration with environment variables:

```bash
# Use memory backend (default)
INFERADB__ENGINE__STORAGE=memory

# Use Ledger backend
INFERADB__ENGINE__STORAGE=ledger
INFERADB__ENGINE__LEDGER__ENDPOINT=http://ledger.inferadb:50051
INFERADB__ENGINE__LEDGER__CLIENT_ID=engine-001
INFERADB__ENGINE__LEDGER__NAMESPACE_ID=1
INFERADB__ENGINE__LEDGER__VAULT_ID=1
```

## Storage Abstraction

All backends implement the `StorageBackend` trait, providing a consistent interface:

```rust
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Get a value by key
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Set a key-value pair
    async fn set(&self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Delete a key
    async fn delete(&self, key: &[u8]) -> Result<()>;

    /// Get a range of keys
    async fn get_range(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Execute a transaction
    async fn transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut dyn Transaction) -> Result<R> + Send;
}
```

This abstraction ensures:

- **Backend agnostic code** - Write once, run on any backend
- **Easy testing** - Use memory backend in tests, production backend in deployment
- **Zero-cost abstraction** - No runtime overhead beyond the storage layer

## Choosing a Backend

| Criteria          | Memory             | Ledger                  |
| ----------------- | ------------------ | ----------------------- |
| Setup complexity  | ✅ None            | ⚠️ Requires cluster     |
| Performance       | ✅ Sub-microsecond | ✅ Sub-5ms p99          |
| Scalability       | ❌ Single node     | ✅ Horizontal scaling   |
| Persistence       | ❌ RAM only        | ✅ Durable storage      |
| High availability | ❌ No              | ✅ Yes                  |
| Audit trails      | ❌ No              | ✅ Cryptographic        |
| Production ready  | ⚠️ Small scale     | ✅ Yes                  |
| Cost              | ✅ Free            | ⚠️ Infrastructure cost  |

**Quick Decision Guide:**

- **Development/Testing**: Use Memory backend
- **Small production (<10k tuples)**: Memory backend is fine
- **Production (>10k tuples)**: Use Ledger backend
- **Multi-region**: Use Ledger backend
- **High availability required**: Use Ledger backend
- **Compliance/Audit requirements**: Use Ledger backend

## Adding Custom Backends

InferaDB's storage layer is designed to be extensible. To add a new backend:

1. **Implement the `StorageBackend` trait**:

```rust
use async_trait::async_trait;
use inferadb_common_storage::{StorageBackend, Result};

pub struct MyBackend {
    // Your backend implementation
}

#[async_trait]
impl StorageBackend for MyBackend {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Implementation
    }

    async fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        // Implementation
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        // Implementation
    }

    async fn get_range(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        // Implementation
    }

    async fn transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut dyn Transaction) -> Result<R> + Send
    {
        // Implementation
    }
}
```

2. **Add to `BackendType` enum** (in `factory.rs`):

```rust
pub enum BackendType {
    Memory,
    Ledger,
    MyBackend,  // Add your backend
}
```

3. **Update `StorageFactory`**:

```rust
impl StorageFactory {
    pub async fn create(config: StorageConfig) -> Result<Arc<dyn StorageBackend>> {
        match config.backend {
            BackendType::Memory => { /* ... */ }
            BackendType::Ledger => { /* ... */ }
            BackendType::MyBackend => {
                Ok(Arc::new(MyBackend::new()?) as Arc<dyn StorageBackend>)
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

### Ledger Backend

- **Reads**: Network latency + Ledger key lookup (typically <5ms)
- **Writes**: Network latency + Ledger transaction commit (typically <10ms)
- **Space**: Efficient storage with built-in compaction

### Optimization Tips

1. **Batch Operations**: Write multiple tuples in a single transaction
2. **Revision Management**: Use garbage collection to clean old revisions
3. **Caching**: Enable the cache layer for frequently accessed tuples
4. **Indexing**: Both backends maintain indexes automatically

## Migration Between Backends

To migrate from Memory to Ledger (or vice versa):

1. **Export data** from source backend:

```rust
let source = StorageFactory::memory();
let current_rev = source.get_revision().await?;

// Read all tuples
let mut all_tuples = Vec::new();
// (enumerate objects/relations and read)
```

2. **Import data** to target backend:

```rust
let target = StorageFactory::from_str("ledger", config).await?;
target.write(all_tuples).await?;
```

3. **Update configuration** to use new backend

## Troubleshooting

### Memory Backend Issues

**Problem**: Out of memory errors

- **Solution**: Use Ledger backend or implement periodic GC

**Problem**: Data lost on restart

- **Solution**: Memory backend is not persistent by design. Use Ledger for persistence.

### Ledger Backend Issues

**Problem**: Connection errors

- **Solution**: Verify Ledger cluster is running and endpoint is correct

**Problem**: Transaction timeouts

- **Solution**: Check Ledger cluster health, increase transaction timeout if needed

**Problem**: Slow performance

- **Solution**: Check Ledger cluster capacity, optimize batch sizes, enable caching

## See Also

- [Memory Backend Details](./memory.md)
- [Architecture Overview](../architecture.md)
- [Caching Layer](../core/caching.md)
- [Revision Tokens](../core/revision-tokens.md)
