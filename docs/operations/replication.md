# Multi-Region Replication

InferaDB supports active-active multi-region replication for globally distributed deployments with low-latency access and high availability.

## Quick Start

Enable replication in your `config.yaml`:

```yaml
replication:
  enabled: true
  strategy: ActiveActive
  local_region: "us-west-1"
  conflict_resolution: LastWriteWins
  agent:
    max_retries: 5
    retry_delay_ms: 100
    batch_size: 100
  regions:
    - id: "us-west-1"
      name: "US West"
      is_primary: false
      zones:
        - id: "us-west-1a"
          name: "Zone A"
          nodes:
            - id: "node1"
              endpoint: "engine-us-west.internal:50051"
    - id: "eu-central-1"
      name: "EU Central"
      is_primary: false
      zones:
        - id: "eu-central-1a"
          name: "Zone A"
          nodes:
            - id: "node2"
              endpoint: "engine-eu.internal:50051"
  replication_targets:
    us-west-1:
      - eu-central-1
    eu-central-1:
      - us-west-1
```

When replication is enabled:

- All relationship writes are automatically published to the change feed
- The startup log shows replication configuration (strategy, local region)
- The `/healthz` endpoint includes replication health metrics

## Overview

The replication system provides:

- **Multiple Replication Strategies**: ActiveActive, PrimaryReplica, and MultiMaster topologies
- **Conflict Resolution**: Four deterministic strategies including Last-Write-Wins (LWW)
- **Region-Aware Routing**: Intelligent request routing based on operation type and strategy
- **Failure Handling**: Automatic failover, retry logic with exponential backoff
- **Comprehensive Monitoring**: Prometheus metrics for lag, conflicts, and health

## Architecture

The replication system consists of four main components:

### 1. Topology (`inferadb-engine-repl/topology.rs`)

Defines the multi-region infrastructure with a hierarchical structure:

```text
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
use inferadb_engine_repl::{TopologyBuilder, RegionId, ZoneId, NodeId, ReplicationStrategy};

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

### 2. Conflict Resolution (`inferadb-engine-repl/conflict.rs`)

Handles conflicts when the same tuple is modified concurrently in different regions.

**Conflict Resolution Strategies:**

#### Last-Write-Wins (LWW)

Uses timestamp to determine winner. If timestamps are equal, uses source node as tiebreaker.

```rust
use inferadb_engine_repl::{ConflictResolver, ConflictResolutionStrategy};

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

### 3. Replication Agent (`inferadb-engine-repl/agent.rs`)

Subscribes to local changes and replicates them to remote regions.

**Features:**

- **Batched Replication**: Groups changes for efficient transmission
- **Retry Logic**: Exponential backoff with configurable max retries
- **Failure Tracking**: Monitors consecutive failures per target
- **Metrics Integration**: Records replication lag, conflicts, failures

**Configuration:**

```rust
use inferadb_engine_repl::ReplicationConfig;
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
use inferadb_engine_repl::ReplicationAgent;
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

### 4. Region-Aware Router (`inferadb-engine-repl/router.rs`)

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
use inferadb_engine_repl::{Router, RequestType};

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

#### Load Balancing Strategies

The router supports configurable load balancing across healthy nodes within a region:

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **RoundRobin** (default) | Distributes requests evenly across all healthy nodes | Production deployments with multiple nodes |
| **FirstAvailable** | Always routes to the first healthy node | Testing or single-node deployments |

**Configuration:**

```rust
use inferadb_engine_repl::{Router, LoadBalancingStrategy};

// Default: round-robin load balancing
let router = Router::new(topology.clone());

// Explicit round-robin
let router = Router::with_strategy(topology.clone(), LoadBalancingStrategy::RoundRobin);

// First available (no load balancing)
let router = Router::with_strategy(topology.clone(), LoadBalancingStrategy::FirstAvailable);
```

### 5. Runtime Topology Management (`inferadb-engine-repl/topology.rs`)

The `TopologyManager` enables dynamic topology updates at runtime without service restarts.

**Features:**

- Add/remove nodes dynamically as they scale
- Update node health status based on health checks
- Replace entire topology for configuration changes
- Event broadcasting for topology change notifications
- Heartbeat tracking for stale node detection

**Usage:**

```rust
use inferadb_engine_repl::{TopologyManager, TopologyEvent, NodeStatus, NodeId, RegionId, ZoneId, Node};

// Create manager from existing topology
let manager = TopologyManager::new(topology);

// Update node status (e.g., from health check)
manager.update_node_status(
    &RegionId::new("us-west-1"),
    &ZoneId::new("us-west-1a"),
    &NodeId::new("node1"),
    NodeStatus::Degraded,
).await;

// Add a new node dynamically
let new_node = Node::new(NodeId::new("node3"), "localhost:50053".to_string());
manager.add_node(
    &RegionId::new("us-west-1"),
    &ZoneId::new("us-west-1a"),
    new_node,
).await?;

// Remove a node
manager.remove_node(
    &RegionId::new("us-west-1"),
    &ZoneId::new("us-west-1a"),
    &NodeId::new("node3"),
).await?;

// Record heartbeat from health check
manager.record_heartbeat(
    &RegionId::new("us-west-1"),
    &ZoneId::new("us-west-1a"),
    &NodeId::new("node1"),
).await;

// Mark nodes as unreachable if no heartbeat in 30 seconds
manager.check_stale_nodes(30_000).await;
```

**Event Subscription:**

Subscribe to topology changes for reactive updates:

```rust
let mut receiver = manager.subscribe();

tokio::spawn(async move {
    while let Ok(event) = receiver.recv().await {
        match event {
            TopologyEvent::NodeAdded { region_id, zone_id, node_id } => {
                println!("Node added: {}", node_id);
            }
            TopologyEvent::NodeRemoved { region_id, zone_id, node_id } => {
                println!("Node removed: {}", node_id);
            }
            TopologyEvent::NodeStatusChanged { node_id, old_status, new_status, .. } => {
                println!("Node {} status: {:?} -> {:?}", node_id, old_status, new_status);
            }
            TopologyEvent::TopologyReplaced => {
                println!("Topology fully replaced");
            }
            _ => {}
        }
    }
});
```

### 6. Discovery Integration (`inferadb-engine-repl/discovery.rs`)

Automatically construct replication topology from service discovery (Kubernetes or Tailscale).

**Building Topology from Discovery:**

```rust
use inferadb_engine_repl::{
    DiscoveryTopologyConfig, DiscoveredEndpoint, TopologyFromDiscovery,
    ReplicationStrategy,
};

// Configure topology construction
let config = DiscoveryTopologyConfig {
    local_region: "us-west-1".to_string(),
    strategy: ReplicationStrategy::ActiveActive,
    default_zone: "default".to_string(),
};

// Build from discovered endpoints
let mut builder = TopologyFromDiscovery::new(config);

// Add endpoints from service discovery
builder.add_endpoint(DiscoveredEndpoint::new(
    "http://engine-0.engine-headless:8081".to_string(),
    "us-west-1".to_string(),
    "node-0".to_string(),
));

builder.add_endpoint(
    DiscoveredEndpoint::new(
        "http://engine-eu.tailnet:8081".to_string(),
        "eu-central-1".to_string(),
        "node-eu-0".to_string(),
    )
    .with_zone(Some("eu-central-1a".to_string()))
    .with_health(true),
);

let topology = builder.build()?;
```

**Runtime Topology Updates from Discovery:**

```rust
use inferadb_engine_repl::update_topology_from_discovery;

// Update existing topology manager with new discovered endpoints
update_topology_from_discovery(&manager, endpoints, "default").await;
```

This integrates with the `inferadb-engine-discovery` crate which provides:

- **Kubernetes discovery**: Resolves services to pod IPs
- **Tailscale discovery**: Resolves via MagicDNS across regions

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
use inferadb_engine_repl::{ChangeFeed, Change, Operation};

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

## Health Endpoints

The `/healthz` endpoint includes replication health information when replication is enabled:

```json
{
  "status": "healthy",
  "service": "inferadb-engine",
  "version": "0.1.0",
  "uptime_seconds": 3600,
  "timestamp": 1702000000,
  "details": {
    "storage": { "status": "healthy", "message": "Storage operational" },
    "cache": { "status": "healthy", "message": "Cache operational" },
    "auth": { "status": "healthy", "message": "Auth ready" },
    "replication": {
      "status": "healthy",
      "enabled": true,
      "published": 12345,
      "subscribers": 2,
      "dropped": 0,
      "message": "Published: 12345, Subscribers: 2, Dropped: 0"
    }
  }
}
```

**Replication health fields:**

- `enabled`: Whether replication is active
- `published`: Total number of change events published
- `subscribers`: Number of active change feed subscribers
- `dropped`: Number of events dropped due to buffer overflow
- `status`: `healthy` if operating normally, `degraded` if issues detected

## Monitoring

The replication system exposes comprehensive Prometheus metrics:

### Counters

| Metric                                                  | Description                                 |
| ------------------------------------------------------- | ------------------------------------------- |
| `inferadb_engine_replication_changes_total`             | Total changes replicated                    |
| `inferadb_engine_replication_failures_total`            | Total replication failures                  |
| `inferadb_engine_replication_conflicts_total`           | Total conflicts detected                    |
| `inferadb_engine_replication_conflicts_resolved_local`  | Conflicts resolved by keeping local change  |
| `inferadb_engine_replication_conflicts_resolved_remote` | Conflicts resolved by keeping remote change |

### Gauges

| Metric                                          | Description                 |
| ----------------------------------------------- | --------------------------- |
| `inferadb_engine_replication_lag_milliseconds`  | Current replication lag     |
| `inferadb_engine_replication_targets_connected` | Number of connected targets |
| `inferadb_engine_replication_targets_total`     | Total configured targets    |

### Histograms

| Metric                                         | Description                        |
| ---------------------------------------------- | ---------------------------------- |
| `inferadb_engine_replication_batch_size`       | Distribution of batch sizes        |
| `inferadb_engine_replication_duration_seconds` | Duration of replication operations |

**Example Prometheus Queries:**

```promql
# Replication lag
inferadb_engine_replication_lag_milliseconds

# Conflict rate (conflicts per second)
rate(inferadb_engine_replication_conflicts_total[5m])

# Replication throughput (changes per second)
rate(inferadb_engine_replication_changes_total[5m])

# Failure rate
rate(inferadb_engine_replication_failures_total[5m])

# Target health
inferadb_engine_replication_targets_connected / inferadb_engine_replication_targets_total
```

## Configuration

### Environment Variables

```bash
# Replication agent settings
export INFERADB__ENGINE__REPLICATION__MAX_RETRIES=5
export INFERADB__ENGINE__REPLICATION__RETRY_DELAY_MS=100
export INFERADB__ENGINE__REPLICATION__BATCH_SIZE=100
export INFERADB__ENGINE__REPLICATION__REQUEST_TIMEOUT_SECS=10
export INFERADB__ENGINE__REPLICATION__BUFFER_SIZE=10000
```

### YAML Configuration

```yaml
engine:
  replication:
    enabled: true

    # Replication strategy: active_active, primary_replica, or multi_master
    strategy: "active_active"

    # Local region identifier
    local_region: "us-west-1"

    # Conflict resolution: lww, source_priority, insert_wins
    conflict_resolution: "lww"

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
engine:
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
engine:
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
engine:
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

**Symptoms:** `inferadb_engine_replication_lag_milliseconds` increasing

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

**Symptoms:** High `inferadb_engine_replication_conflicts_total` rate

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

**Symptoms:** Increasing `inferadb_engine_replication_failures_total`

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

**Symptoms:** `inferadb_engine_replication_targets_connected` < `inferadb_engine_replication_targets_total`

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
engine:
  replication:
    agent:
      batch_size: 100 # Good default
```

### Retry Configuration

Aggressive retries = faster recovery, more load
Conservative retries = less load, slower recovery

**Recommendation:** 5 retries with 100ms base delay

```yaml
engine:
  replication:
    agent:
      max_retries: 5
      retry_delay_ms: 100
```

### Buffer Size

Larger buffer = handles spikes better, more memory
Smaller buffer = less memory, may drop changes under load

**Recommendation:** 10,000 for production

```yaml
engine:
  replication:
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
- Monitor `inferadb_engine_replication_batch_size` histogram

## Kubernetes Deployment

### StatefulSet for Consistent Node IDs

For replication to work correctly, each node needs a stable, unique identifier. Use a **StatefulSet** deployment to ensure consistent node IDs across restarts.

**Why StatefulSet?**

- Provides stable network identities (`pod-name-0`, `pod-name-1`, etc.)
- Enables consistent node IDs for replication topology
- Supports ordered, graceful deployment and scaling
- Maintains persistent storage across pod restarts

**Example StatefulSet configuration:**

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: inferadb-engine
spec:
  serviceName: inferadb-engine-headless
  replicas: 3
  podManagementPolicy: Parallel  # Faster rollouts
  selector:
    matchLabels:
      app.kubernetes.io/name: inferadb-engine
  template:
    metadata:
      labels:
        app.kubernetes.io/name: inferadb-engine
    spec:
      containers:
      - name: engine
        image: inferadb-engine:latest
        env:
        # Use pod name as node ID for consistent identification
        - name: INFERADB__ENGINE__NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        # Use pod namespace for region awareness
        - name: INFERADB__ENGINE__LOCAL_REGION
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8081
          name: grpc
```

**Headless Service for pod-to-pod communication:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: inferadb-engine-headless
spec:
  clusterIP: None
  selector:
    app.kubernetes.io/name: inferadb-engine
  ports:
  - port: 8081
    name: grpc
```

### Multi-Region with Tailscale

For multi-region deployments, use Tailscale mesh networking to connect clusters across cloud providers.

**Enable in Helm values:**

```yaml
discovery:
  mode: "tailscale"
  tailscale:
    enabled: true
    localCluster: "us-west-1"
    remoteClusters:
    - name: "eu-central-1"
      tailscaleDomain: "eu-central-1.ts.net"
      serviceName: "inferadb-engine"
      port: 8081
      regionId: "eu-central-1"

replication:
  enabled: true
  strategy: "ActiveActive"
  localRegion: "us-west-1"
  conflictResolution: "LastWriteWins"
```

**Tailscale sidecar is automatically injected when `discovery.tailscale.enabled: true`.**

### Region-Aware Scheduling

Use node labels and topology spread constraints to distribute pods across zones:

```yaml
topologySpreadConstraints:
- maxSkew: 1
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: DoNotSchedule
  labelSelector:
    matchLabels:
      app.kubernetes.io/name: inferadb-engine
```

### ConfigMap for Replication Configuration

For complex topologies, use a ConfigMap with full replication configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: inferadb-replication-config
data:
  replication.yaml: |
    replication:
      enabled: true
      strategy: ActiveActive
      local_region: us-west-1
      conflict_resolution: LastWriteWins
      regions:
        - id: us-west-1
          name: US West
          zones:
            - id: us-west-1a
              nodes:
                - id: engine-0
                  endpoint: inferadb-engine-0.inferadb-engine-headless:8081
                - id: engine-1
                  endpoint: inferadb-engine-1.inferadb-engine-headless:8081
        - id: eu-central-1
          name: EU Central
          zones:
            - id: eu-central-1a
              nodes:
                - id: engine-eu-0
                  endpoint: inferadb-engine-0.inferadb-engine-headless.eu-central-1.ts.net:8081
      replication_targets:
        us-west-1:
          - eu-central-1
        eu-central-1:
          - us-west-1
```

## API Reference

### Complete API documentation

- **Topology API**: See [`inferadb-engine-repl/src/topology.rs`](../crates/inferadb-engine-repl/src/topology.rs)
- **Conflict Resolution API**: See [`inferadb-engine-repl/src/conflict.rs`](../crates/inferadb-engine-repl/src/conflict.rs)
- **Replication Agent API**: See [`inferadb-engine-repl/src/agent.rs`](../crates/inferadb-engine-repl/src/agent.rs)
- **Router API**: See [`inferadb-engine-repl/src/router.rs`](../crates/inferadb-engine-repl/src/router.rs)

## Related Documentation

- [Architecture Overview](architecture.md) - System design
- [Revision Tokens](revision-tokens.md) - Snapshot consistency
- [Observability](observability.md) - Metrics and tracing
- [Configuration](configuration.md) - Configuration reference

## Examples

Complete examples are available in the integration tests:

- [`crates/inferadb-engine-repl/tests/replication_integration.rs`](../crates/inferadb-engine-repl/tests/replication_integration.rs)
