# Revision Tokens (Zookies)

InferaDB implements "zookie"-style revision tokens to provide snapshot consistency for distributed reads. This ensures that clients can perform causally consistent reads even in multi-region deployments.

## Overview

Revision tokens are opaque identifiers that capture the state of the authorization database at a specific point in time. They enable:

1. **Snapshot Isolation** - Read data as it existed at a specific revision
2. **Causal Consistency** - Ensure reads reflect writes that causally precede them
3. **Linearizability** - Optional strong consistency guarantees

## Token Structure

A revision token contains:

```rust
pub struct RevisionToken {
    pub node_id: String,              // Node that generated the token
    pub revision: u64,                 // Revision number at that node
    pub vector_clock: HashMap<String, u64>,  // Vector clock for causality
}
```

### Example Token

```json
{
  "node_id": "node-us-west-1",
  "revision": 42,
  "vector_clock": {
    "node-us-west-1": 42,
    "node-us-east-1": 38,
    "node-eu-west-1": 35
  }
}
```

## Serialization

Tokens are serialized as base64-encoded JSON for transmission:

```text
eyJub2RlX2lkIjoibm9kZS11cy13ZXN0LTEiLCJyZXZpc2lvbiI6NDIsInZlY3Rvcl9jbG9jayI6eyJub2RlLXVzLXdlc3QtMSI6NDIsIm5vZGUtdXMtZWFzdC0xIjozOCwibm9kZS1ldS13ZXN0LTEiOjM1fX0=
```

This format allows tokens to be:

- Included in HTTP headers
- Passed as query parameters
- Stored in cookies
- Used in gRPC metadata

## Usage Patterns

### Write-Then-Read Consistency

After writing data, use the returned token to ensure subsequent reads see the write:

```rust
// Write tuples
let revision = store.write(tuples).await?;
let token = RevisionToken::new("node1", revision.0);

// Later, read with token
let reader = SnapshotReader::new(store);
let tuples = reader.read_at_token(&key, &token).await?;
// Guaranteed to see the write
```

### HTTP API Example

```http
POST /write
{"tuples": [...]}

Response:
{
  "revision": 42,
  "token": "eyJub2RlX2lkIjoibm9kZTEiLCJyZXZpc2lvbiI6NDIsInZlY3Rvcl9jbG9jayI6eyJub2RlMSI6NDJ9fQ=="
}

GET /check?token=eyJub2RlX2lkIjoibm9kZTEiLCJyZXZpc2lvbiI6NDIsInZlY3Rvcl9jbG9jayI6eyJub2RlMSI6NDJ9fQ==
// Read will see the write
```

## Causality Checking

Tokens support causality operations for distributed scenarios:

### Happens-After Relation

Check if one token happens after another:

```rust
let token1 = RevisionToken::new("node1", 10);
let token2 = RevisionToken::new("node1", 20);

assert!(token2.is_after(&token1));  // true
assert!(!token1.is_after(&token2)); // false
```

### Multi-Node Causality

With vector clocks, causality works across nodes:

```rust
let mut clock1 = HashMap::new();
clock1.insert("node1".to_string(), 10);
clock1.insert("node2".to_string(), 5);
let token1 = RevisionToken::with_vector_clock("node1", 10, clock1);

let mut clock2 = HashMap::new();
clock2.insert("node1".to_string(), 12);
clock2.insert("node2".to_string(), 8);
let token2 = RevisionToken::with_vector_clock("node1", 12, clock2);

assert!(token2.is_after(&token1));  // All clocks advanced
```

### Concurrent Operations

Detect when operations are concurrent (neither happens before the other):

```rust
let mut clock_a = HashMap::new();
clock_a.insert("node1".to_string(), 10);
clock_a.insert("node2".to_string(), 5);
let token_a = RevisionToken::with_vector_clock("node1", 10, clock_a);

let mut clock_b = HashMap::new();
clock_b.insert("node1".to_string(), 8);
clock_b.insert("node2".to_string(), 12);
let token_b = RevisionToken::with_vector_clock("node2", 12, clock_b);

assert!(token_a.is_concurrent_with(&token_b));  // Concurrent writes
```

## Snapshot Reads

The `SnapshotReader` provides consistent reads at specific tokens:

```rust
use inferadb_engine_repl::snapshot::SnapshotReader;
use std::sync::Arc;

let store = Arc::new(MemoryBackend::new());
let reader = SnapshotReader::new(store.clone());

// Get current token
let token = reader.current_token("node1".to_string()).await?;

// Write more data
store.write(new_tuples).await?;

// Read at old token - won't see new writes
let tuples = reader.read_at_token(&key, &token).await?;
```

### Timeout Handling

Snapshot reads block until the revision is available or timeout:

```rust
use std::time::Duration;

let reader = SnapshotReader::with_timeout(
    store,
    Duration::from_secs(10)  // 10 second timeout
);

// If revision not available within 10s, returns error
let result = reader.read_at_token(&key, &future_token).await;
match result {
    Ok(tuples) => println!("Got tuples: {:?}", tuples),
    Err(_) => println!("Timeout waiting for revision"),
}
```

## Token Validation

Tokens are validated before use:

```rust
let token = RevisionToken::new("node1", 42);

// Validate token
token.validate()?;  // Checks structure is valid

// Invalid tokens are rejected
let bad_token = RevisionToken::new("", 0);
assert!(bad_token.validate().is_err());
```

### Validation Rules

1. **Node ID must not be empty**
2. **Revision must be > 0**
3. **Vector clock must not be empty**
4. **Vector clock must contain node's entry**
5. **Node's clock entry must match revision**

## Token Merging

For replication scenarios, tokens can be merged:

```rust
let token1 = RevisionToken::new("node1", 10);
let token2 = RevisionToken::new("node2", 15);

let merged = token1.merge(&token2);
// merged.vector_clock contains max of both clocks
// merged is causally after both token1 and token2
```

This is useful for:

- **Replication acknowledgment** - Track when all replicas have seen a write
- **Distributed transactions** - Coordinate across multiple nodes
- **Cache invalidation** - Ensure all caches are up to date

## Performance Characteristics

### Token Operations

- **Creation**: O(1) for single node, O(n) for vector clock with n nodes
- **Validation**: O(n) where n is vector clock size
- **Causality check**: O(n) where n is vector clock size
- **Encoding**: O(n) for JSON serialization
- **Decoding**: O(n) for JSON deserialization

All operations typically complete in **<1ms** for typical vector clock sizes (<10 nodes).

### Snapshot Reads

- **Cache hit**: ~100μs
- **Available revision**: ~1ms
- **Unavailable revision**: Blocks until available or timeout
- **Polling overhead**: 10ms intervals

## Advanced Usage

### Session Consistency

Maintain a session token across requests:

```rust
struct Session {
    token: RevisionToken,
}

impl Session {
    async fn write(&mut self, tuples: Vec<Tuple>) -> Result<()> {
        let revision = store.write(tuples).await?;
        self.token = RevisionToken::new("node1", revision.0);
        Ok(())
    }

    async fn read(&self, key: &TupleKey) -> Result<Vec<Tuple>> {
        let reader = SnapshotReader::new(store);
        reader.read_at_token(key, &self.token).await
    }
}
```

### Multi-Region Reads

Read from the closest region while ensuring consistency:

```rust
// Write to primary region
let token = write_to_primary(tuples).await?;

// Read from local region with token
let tuples = read_from_local_region(key, token).await?;
// Blocks until local region catches up to token revision
```

### Linearizable Reads

For strong consistency, read from the latest revision:

```rust
// Get latest token
let token = reader.current_token("node1").await?;

// Read at latest revision
let tuples = reader.read_at_token(&key, &token).await?;
// Guaranteed to see all writes up to current time
```

## Comparison with Other Systems

### Spanner TrueTime

- **Spanner**: Uses hardware clock synchronization
- **InferaDB**: Uses logical revision numbers and vector clocks
- **Trade-off**: Spanner provides bounded staleness, InferaDB provides causal consistency

### DynamoDB Consistent Reads

- **DynamoDB**: Strongly consistent reads go to leader
- **InferaDB**: Snapshot reads can go to any replica with sufficient revision
- **Trade-off**: DynamoDB has higher latency, InferaDB has better read scalability

### MongoDB Read Concerns

- **MongoDB**: Read concern "snapshot" provides point-in-time consistency
- **InferaDB**: Revision tokens provide similar guarantees with explicit control
- **Trade-off**: Similar models, InferaDB tokens are more explicit

## Best Practices

### 1. Use Tokens for Critical Reads

Use tokens when consistency matters:

```rust
// Critical: Need to see our own write
let token = write_tuples(tuples).await?;
let check = check_with_token(subject, resource, permission, token).await?;

// Non-critical: Eventual consistency is fine
let check = check(subject, resource, permission).await?;
```

### 2. Set Appropriate Timeouts

Choose timeouts based on SLA requirements:

```rust
// Interactive request - short timeout
let reader = SnapshotReader::with_timeout(store, Duration::from_millis(100));

// Background job - longer timeout
let reader = SnapshotReader::with_timeout(store, Duration::from_secs(30));
```

### 3. Cache Token Validations

Validate tokens once and reuse:

```rust
let token = RevisionToken::decode(&token_string)?;
token.validate()?;  // Validate once

// Reuse validated token
for key in keys {
    let tuples = reader.read_at_token(&key, &token).await?;
}
```

### 4. Monitor Token Age

Track token age to detect replication lag:

```rust
let current = reader.current_token("node1").await?;
let age = current.revision - client_token.revision;

if age > 1000 {
    warn!("Client token is {} revisions behind", age);
}
```

## Troubleshooting

### Token Validation Errors

```text
Error: Invalid revision token
```

**Causes**:

- Malformed base64 encoding
- Invalid JSON structure
- Empty node ID
- Zero revision number
- Missing vector clock entries

**Solution**: Ensure token was generated correctly and not corrupted.

### Timeout Waiting for Revision

```text
Error: Timeout waiting for revision to become available
```

**Causes**:

- Replication lag
- Network partition
- Node failure
- Client has token from future

**Solutions**:

- Increase timeout duration
- Check replication health
- Verify network connectivity
- Ensure client clock is synchronized

### Concurrent Token Conflicts

When two tokens are concurrent, neither is "newer":

```rust
if token_a.is_concurrent_with(&token_b) {
    // Conflict: Need conflict resolution strategy
    let merged = token_a.merge(&token_b);
    // Use merged token for subsequent operations
}
```

## Future Enhancements

### Planned Features

1. **Token Compression** - More efficient encoding for large vector clocks
2. **Token Expiry** - Automatic token invalidation after time window
3. **Bounded Staleness** - Maximum allowed staleness for reads
4. **Token-Based Cache** - Cache entries keyed by token
5. **Token Metrics** - Track token usage and staleness distributions

## References

- [Vector Clocks Paper](https://en.wikipedia.org/wiki/Vector_clock)
- [Lamport Timestamps](https://en.wikipedia.org/wiki/Lamport_timestamp)
- [Google Spanner](https://research.google/pubs/pub39966/)
- [Zanzibar Paper](https://research.google/pubs/pub48190/) - Original zookie concept
