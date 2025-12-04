# Multi-Region Replication

InferaDB supports active-active multi-region replication for globally distributed deployments with low-latency access and high availability.

## Overview

The replication system provides:

- **Multiple Replication Strategies**: ActiveActive, PrimaryReplica, and MultiMaster topologies
- **Conflict Resolution**: Four deterministic strategies including Last-Write-Wins (LWW)
- **Region-Aware Routing**: Intelligent request routing based on operation type and strategy
- **Failure Handling**: Automatic failover, retry logic with exponential backoff
- **Comprehensive Monitoring**: Prometheus metrics for lag, conflicts, and health

## Architecture

The replication system consists of four main components:

### 1. Topology (`infera-repl/topology.rs`)

Defines the multi-region infrastructure with a hierarchical structure:

```
Region (e.g., "us-west-1")
  └─ Zone (e.g., "us-west-1a")
      └─ Node (e.g., "node1" at "localhost:50051")
```

**Key Types:**

- `RegionId` - Unique identifier for a geographic region
- `ZoneId` - Availability zone within a region
- `NodeId` - Individual server instance
- `ReplicationStrategy` - Topology pattern (ActiveActive, PrimaryReplica, MultiMaster)

**Example:**

```rust
use infera_repl::{TopologyBuilder, RegionId, ZoneId, NodeId, ReplicationStrategy};

let topology = TopologyBuilder::new(
    ReplicationStrategy::ActiveActive,
    RegionId::new("us-west-1")
)
.add_region(RegionId::new("us-west-1"), "US West".to_string(), false)
.add_zone(
    RegionId::new("us-west-1"),
    ZoneId::new("us-west-1a"),
    "Zone A".to_string(),
)
.add_node(
    RegionId::new("us-west-1"),
    ZoneId::new("us-west-1a"),
    NodeId::new("node1"),
    "localhost:50051".to_string(),
)
.add_region(RegionId::new("eu-central-1"), "EU Central".to_string(), false)
.add_zone(
    RegionId::new("eu-central-1"),
    ZoneId::new("eu-central-1a"),
    "Zone A".to_string(),
)
.add_node(
    RegionId::new("eu-central-1"),
    ZoneId::new("eu-central-1a"),
    NodeId::new("node2"),
    "localhost:50052".to_string(),
)
.set_replication_targets(
    RegionId::new("us-west-1"),
    vec![RegionId::new("eu-central-1")],
)
.set_replication_targets(
    RegionId::new("eu-central-1"),
    vec![RegionId::new("us-west-1")],
)
.build()?;
```

### 2. Conflict Resolution (`infera-repl/conflict.rs`)

Handles conflicts when the same tuple is modified concurrently in different regions.

**Conflict Resolution Strategies:**

#### Last-Write-Wins (LWW)

Uses timestamp to determine winner. If timestamps are equal, uses source node as tiebreaker.

```rust
use infera_repl::{ConflictResolver, ConflictResolutionStrategy};

let resolver = ConflictResolver::new(ConflictResolutionStrategy::LastWriteWins);
```

**Best for:** Simple deployments with synchronized clocks

#### Source Priority

Assigns priority to regions. Higher-priority regions always win conflicts.

```rust
let resolver = ConflictResolver::new(ConflictResolutionStrategy::SourcePriority)
    .with_region_priorities(vec![
        "us-west".to_string(),      // Priority 0 (lowest)
        "eu-central".to_string(),   // Priority 1
        "ap-southeast".to_string(), // Priority 2 (highest)
    ]);
```

**Best for:** Primary/backup scenarios or data sovereignty requirements

#### Insert Wins

Inserts always win over deletes, preventing data loss.

```rust
let resolver = ConflictResolver::new(ConflictResolutionStrategy::InsertWins);
```

**Best for:** Systems where data preservation is critical

#### Custom

Application-defined resolution logic.

```rust
let resolver = ConflictResolver::new(ConflictResolutionStrategy::Custom);
// Implement custom resolution in application code
```

**Best for:** Complex business rules

### 3. Replication Agent (`infera-repl/agent.rs`)

Subscribes to local changes and replicates them to remote regions.

**Features:**

- **Batched Replication**: Groups changes for efficient transmission
- **Retry Logic**: Exponential backoff with configurable max retries
- **Failure Tracking**: Monitors consecutive failures per target
- **Metrics Integration**: Records replication lag, conflicts, failures

**Configuration:**

```rust
use infera_repl::ReplicationConfig;
use std::time::Duration;

let config = ReplicationConfig {
    max_retries: 5,
    retry_delay: Duration::from_millis(100),
    batch_size: 100,
    request_timeout: Duration::from_secs(10),
    buffer_size: 10000,
};
```

**Usage:**

```rust
use infera_repl::ReplicationAgent;
use std::sync::Arc;
use tokio::sync::RwLock;

let agent = ReplicationAgent::new(
    Arc::new(RwLock::new(topology)),
    Arc::new(change_feed),
    Arc::new(store),
    Arc::new(conflict_resolver),
    config,
);

// Start replication
agent.start().await?;

// Get statistics
let stats = agent.stats().await;
println!("Changes replicated: {}", stats.changes_replicated);
println!("Failures: {}", stats.replication_failures);
```

### 4. Region-Aware Router (`infera-repl/router.rs`)

Routes requests to appropriate regions based on operation type and replication strategy.

**Routing Rules:**

| Strategy           | Read Requests | Write Requests |
| ------------------ | ------------- | -------------- |
| **ActiveActive**   | Local region  | Local region   |
| **PrimaryReplica** | Local region  | Primary region |
| **MultiMaster**    | Local region  | Local region   |

**Failover:** If local region is unavailable, automatically fails over to healthy regions.

**Usage:**

```rust
use infera_repl::{Router, RequestType};

let router = Router::new(Arc::new(RwLock::new(topology)));

// Route a read request
let decision = router.route(RequestType::Read).await?;
println!("Route to: {} at {}", decision.node_id, decision.endpoint);

// Route a write request
let decision = router.route(RequestType::Write).await?;

// Check region availability
if router.is_region_available(&RegionId::new("us-west-1")).await {
    println!("Region is healthy");
}
```

## Replication Strategies

### Active-Active

All regions can accept both reads and writes. Changes are replicated bi-directionally.

**Pros:**

- Lowest write latency (write locally)
- Highest availability (any region can handle requests)
- Best user experience globally

**Cons:**

- Must handle conflicts
- More complex than primary-replica
- Requires careful conflict resolution strategy

**Best for:** Global applications requiring low latency everywhere

**Configuration:**

```rust
let topology = TopologyBuilder::new(
    ReplicationStrategy::ActiveActive,
    local_region,
)
// Add regions with is_primary = false for all
.build()?;
```

### Primary-Replica

One primary region accepts writes; replicas serve reads only.

**Pros:**

- No conflicts (single write source)
- Simpler to reason about
- Strong consistency guarantees

**Cons:**

- Higher write latency for remote clients
- Primary is single point of failure for writes
- Read-only replicas during primary outage

**Best for:** Applications with strong consistency requirements

**Configuration:**

```rust
let topology = TopologyBuilder::new(
    ReplicationStrategy::PrimaryReplica,
    local_region,
)
.add_region(RegionId::new("us-west-1"), "US West".to_string(), true)  // primary
.add_region(RegionId::new("eu-central-1"), "EU Central".to_string(), false)  // replica
.build()?;
```

### Multi-Master

Different regions can accept writes for different tenants/namespaces.

**Pros:**

- Data locality (tenant data stays in region)
- Compliance friendly (GDPR, data residency)
- Scalable (partitioned by tenant)

**Cons:**

- Requires partitioning strategy
- More complex routing
- Cross-tenant queries may be slower

**Best for:** Multi-tenant SaaS with data residency requirements

**Configuration:**

```rust
let topology = TopologyBuilder::new(
    ReplicationStrategy::MultiMaster,
    local_region,
)
// Add regions, route based on tenant
.build()?;
```

## Change Feed

The replication system uses the change feed to track all tuple modifications.

**Publishing Changes:**

```rust
use infera_repl::{ChangeFeed, Change, Operation};

let change_feed = ChangeFeed::new();

// Publish a change
let change = Change::insert(revision, tuple);
change_feed.publish(change).await?;
```

**Subscribing to Changes:**

```rust
// Subscribe to all changes
let mut stream = change_feed.subscribe().await?;

// Subscribe with filter
let mut stream = change_feed
    .subscribe_filtered("document".to_string())
    .await?;

// Receive changes
while let Some(change) = stream.recv().await {
    println!("Change: {:?}", change);
}
```

## Monitoring

The replication system exposes comprehensive Prometheus metrics:

### Counters

| Metric                                           | Description                                 |
| ------------------------------------------------ | ------------------------------------------- |
| `inferadb_replication_changes_total`             | Total changes replicated                    |
| `inferadb_replication_failures_total`            | Total replication failures                  |
| `inferadb_replication_conflicts_total`           | Total conflicts detected                    |
| `inferadb_replication_conflicts_resolved_local`  | Conflicts resolved by keeping local change  |
| `inferadb_replication_conflicts_resolved_remote` | Conflicts resolved by keeping remote change |

### Gauges

| Metric                                   | Description                 |
| ---------------------------------------- | --------------------------- |
| `inferadb_replication_lag_milliseconds`  | Current replication lag     |
| `inferadb_replication_targets_connected` | Number of connected targets |
| `inferadb_replication_targets_total`     | Total configured targets    |

### Histograms

| Metric                                  | Description                        |
| --------------------------------------- | ---------------------------------- |
| `inferadb_replication_batch_size`       | Distribution of batch sizes        |
| `inferadb_replication_duration_seconds` | Duration of replication operations |

**Example Prometheus Queries:**

```promql
# Replication lag
inferadb_replication_lag_milliseconds

# Conflict rate (conflicts per second)
rate(inferadb_replication_conflicts_total[5m])

# Replication throughput (changes per second)
rate(inferadb_replication_changes_total[5m])

# Failure rate
rate(inferadb_replication_failures_total[5m])

# Target health
inferadb_replication_targets_connected / inferadb_replication_targets_total
```

## Configuration

### Environment Variables

```bash
# Replication agent settings
export INFERADB__REPLICATION__MAX_RETRIES=5
export INFERADB__REPLICATION__RETRY_DELAY_MS=100
export INFERADB__REPLICATION__BATCH_SIZE=100
export INFERADB__REPLICATION__REQUEST_TIMEOUT_SECS=10
export INFERADB__REPLICATION__BUFFER_SIZE=10000
```

### YAML Configuration

```yaml
replication:
    # Replication strategy: active_active, primary_replica, or multi_master
    strategy: active_active

    # Local region identifier
    local_region: us-west-1

    # Conflict resolution: lww, source_priority, insert_wins, or custom
    conflict_resolution: lww

    # Region priorities (for source_priority strategy)
    region_priorities:
        - us-west-1
        - eu-central-1
        - ap-southeast-1

    # Agent configuration
    agent:
        max_retries: 5
        retry_delay_ms: 100
        batch_size: 100
        request_timeout_secs: 10
        buffer_size: 10000

    # Topology definition
    regions:
        - id: us-west-1
          name: "US West 1"
          is_primary: false
          zones:
              - id: us-west-1a
                name: "Zone A"
                nodes:
                    - id: node1
                      endpoint: "localhost:50051"

        - id: eu-central-1
          name: "EU Central 1"
          is_primary: false
          zones:
              - id: eu-central-1a
                name: "Zone A"
                nodes:
                    - id: node2
                      endpoint: "localhost:50052"

    # Replication graph (which regions replicate to which)
    replication_targets:
        us-west-1:
            - eu-central-1
        eu-central-1:
            - us-west-1
```

## Deployment Patterns

### Two-Region Active-Active

**Topology:** US West ↔️ EU Central

**Benefits:**

- Low latency for US and EU users
- High availability (either region can fail)
- Simple conflict resolution

**Configuration:**

```yaml
replication:
    strategy: active_active
    local_region: us-west-1
    conflict_resolution: lww
    regions:
        - id: us-west-1
          name: "US West"
          zones: [...]
        - id: eu-central-1
          name: "EU Central"
          zones: [...]
```

### Three-Region Primary-Replica

**Topology:** US West (primary) → EU Central + AP Southeast (replicas)

**Benefits:**

- Strong consistency (single write source)
- Global read performance
- No conflicts

**Configuration:**

```yaml
replication:
    strategy: primary_replica
    local_region: us-west-1 # on primary
    conflict_resolution: lww
    regions:
        - id: us-west-1
          name: "US West"
          is_primary: true
          zones: [...]
        - id: eu-central-1
          name: "EU Central"
          is_primary: false
          zones: [...]
        - id: ap-southeast-1
          name: "AP Southeast"
          is_primary: false
          zones: [...]
```

### Multi-Region Multi-Master

**Topology:** Regional primaries with cross-region replication

**Benefits:**

- Data locality per region
- Compliance friendly
- Scalable by tenant

**Configuration:**

```yaml
replication:
    strategy: multi_master
    local_region: us-west-1
    conflict_resolution: source_priority
    region_priorities:
        - us-west-1
        - eu-central-1
        - ap-southeast-1
```

## Troubleshooting

### High Replication Lag

**Symptoms:** `inferadb_replication_lag_milliseconds` increasing

**Causes:**

- Network latency between regions
- Target region overloaded
- Large batch sizes

**Solutions:**

1. Check network connectivity: `ping <target-endpoint>`
2. Reduce batch size: `INFERADB__REPLICATION__BATCH_SIZE=50`
3. Increase parallelism (add more nodes)
4. Check target region CPU/memory

### Frequent Conflicts

**Symptoms:** High `inferadb_replication_conflicts_total` rate

**Causes:**

- Concurrent writes to same tuples
- Clock skew between regions
- High write volume

**Solutions:**

1. Review conflict resolution strategy
2. Consider primary-replica if consistency is critical
3. Partition data by region (multi-master)
4. Synchronize clocks (NTP)

### Replication Failures

**Symptoms:** Increasing `inferadb_replication_failures_total`

**Causes:**

- Target region down
- Network partitions
- Authentication failures
- Resource exhaustion

**Solutions:**

1. Check target health: `curl <endpoint>/health`
2. Verify credentials/certificates
3. Check firewall rules
4. Review logs: `grep "replication" /var/log/inferadb.log`

### Node Failures

**Symptoms:** `inferadb_replication_targets_connected` < `inferadb_replication_targets_total`

**Causes:**

- Node crashed
- Network partition
- Deployment in progress

**Solutions:**

1. Check node status: `systemctl status inferadb`
2. Review node logs
3. Verify routing configuration
4. Router will automatically failover to healthy nodes

## Performance Tuning

### Batch Size

Larger batches = higher throughput, higher latency
Smaller batches = lower latency, more overhead

**Recommendation:** Start with 100, adjust based on metrics

```yaml
agent:
    batch_size: 100 # Good default
```

### Retry Configuration

Aggressive retries = faster recovery, more load
Conservative retries = less load, slower recovery

**Recommendation:** 5 retries with 100ms base delay

```yaml
agent:
    max_retries: 5
    retry_delay_ms: 100
```

### Buffer Size

Larger buffer = handles spikes better, more memory
Smaller buffer = less memory, may drop changes under load

**Recommendation:** 10,000 for production

```yaml
agent:
    buffer_size: 10000
```

## Best Practices

### 1. Monitor Replication Health

Set up alerts for:

- Replication lag > 100ms
- Conflict rate > 1% of writes
- Target health < 100%
- Failure rate > 0.1%

### 2. Test Failover Scenarios

Regularly test:

- Region failures
- Network partitions
- Conflict resolution
- Recovery time

### 3. Choose the Right Strategy

- **Active-Active**: Global apps, low latency requirement
- **Primary-Replica**: Strong consistency requirement
- **Multi-Master**: Data sovereignty, multi-tenant

### 4. Plan for Conflicts

- Understand your conflict resolution strategy
- Monitor conflict rate
- Design data model to minimize conflicts
- Use application-level conflict resolution if needed

### 5. Capacity Planning

- Replication adds ~20-30% overhead
- Plan for peak write load × (1 + number of replicas)
- Network bandwidth for replication stream
- Monitor `inferadb_replication_batch_size` histogram

## API Reference

### Complete API documentation:

- **Topology API**: See [`infera-repl/src/topology.rs`](../crates/infera-repl/src/topology.rs)
- **Conflict Resolution API**: See [`infera-repl/src/conflict.rs`](../crates/infera-repl/src/conflict.rs)
- **Replication Agent API**: See [`infera-repl/src/agent.rs`](../crates/infera-repl/src/agent.rs)
- **Router API**: See [`infera-repl/src/router.rs`](../crates/infera-repl/src/router.rs)

## Related Documentation

- [Architecture Overview](architecture.md) - System design
- [Revision Tokens](revision-tokens.md) - Snapshot consistency
- [Observability](observability.md) - Metrics and tracing
- [Configuration](configuration.md) - Configuration reference

## Examples

Complete examples are available in the integration tests:

- [`crates/infera-repl/tests/replication_integration.rs`](../crates/infera-repl/tests/replication_integration.rs)
