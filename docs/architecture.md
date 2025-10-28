# Architecture Overview

InferaDB is a high-performance authorization service that implements Relationship-Based Access Control (ReBAC) using a graph-based evaluation model.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         API Layer                            │
│  ┌──────────────────┐              ┌──────────────────┐     │
│  │   REST API       │              │    gRPC API      │     │
│  │  (Axum/Tower)    │              │     (Tonic)      │     │
│  └──────────────────┘              └──────────────────┘     │
└────────────────┬────────────────────────────┬───────────────┘
                 │                            │
                 ▼                            ▼
┌─────────────────────────────────────────────────────────────┐
│                     Core Engine                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │              Policy Evaluator                       │     │
│  │  • Graph Traversal  • Relation Evaluation          │     │
│  │  • Cycle Detection  • Decision Tracing             │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │ IPL Parser │  │ Query Planner │  │  WASM Host   │        │
│  └────────────┘  └──────────────┘  └──────────────┘        │
└────────┬────────────────┬──────────────────┬────────────────┘
         │                │                  │
         ▼                ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   Infrastructure Layer                       │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   Cache     │  │    Store     │  │   Observe    │       │
│  │   (Moka)    │  │  (Memory/    │  │ (Tracing/    │       │
│  │             │  │   FDB)       │  │  Metrics)    │       │
│  └─────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

## Component Overview

### API Layer (`infera-api`)

The API layer provides external interfaces for authorization queries and tuple management.

**REST API** (`src/lib.rs`):
- `/check` - Check if a subject has permission
- `/expand` - Expand a relation into its constituent relationships
- `/write` - Write authorization tuples
- Built with Axum web framework
- JSON request/response format

**gRPC API** (`src/grpc.rs`):
- High-performance binary protocol
- Same operations as REST API
- Built with Tonic framework
- Protocol Buffer definitions in `proto/infera.proto`

### Core Engine (`infera-core`)

The heart of InferaDB, responsible for policy evaluation and authorization decisions.

**IPL Parser** (`src/ipl/`):
- Parses IPL (Infera Policy Language) schemas
- Uses Pest parser generator
- Validates semantic correctness
- Builds Abstract Syntax Tree (AST)

**Policy Evaluator** (`src/evaluator.rs`):
- Evaluates authorization checks
- Implements graph traversal algorithms
- Supports all relation types:
  - Direct relations (`this`)
  - Computed usersets (`viewer from parent`)
  - Union, Intersection, Exclusion operations
  - Tuple-to-userset relations
  - WASM module invocations
- Provides decision tracing for debugging

**Query Optimizer** (`src/optimizer.rs`):
- Analyzes relation definitions
- Creates optimal query plans
- Estimates query costs
- Identifies parallelization opportunities
- Suggests optimizations for expensive queries

**Parallel Evaluator** (`src/parallel.rs`):
- Executes relation branches in parallel
- Manages concurrency limits
- Implements early exit optimizations
- Uses Tokio's async runtime

### Storage Layer (`infera-store`)

Manages tuple storage with revision tracking for snapshot consistency.

**Tuple Store Trait** (`src/lib.rs`):
```rust
#[async_trait]
pub trait TupleStore: Send + Sync {
    async fn read(&self, key: &TupleKey, revision: Revision) -> Result<Vec<Tuple>>;
    async fn write(&self, tuples: Vec<Tuple>) -> Result<Revision>;
    async fn get_revision(&self) -> Result<Revision>;
}
```

**Memory Backend** (`src/memory.rs`):
- In-memory implementation for testing/development
- BTreeMap-based indexing for fast lookups
- Full revision history
- Optimized for reads with RwLock

**FoundationDB Backend** (`src/foundationdb.rs`):
- Production-ready distributed storage (WIP)
- ACID transactions
- Horizontal scalability

### Cache Layer (`infera-cache`)

Intelligent caching of authorization results with automatic invalidation.

**Features**:
- LRU eviction with TTL expiration (Moka async cache)
- Revision-based cache keys for correctness
- Automatic invalidation on writes
- Hit/miss rate tracking
- Statistics reporting

**Cache Key Design**:
```rust
struct CheckCacheKey {
    subject: String,
    resource: String,
    permission: String,
    revision: u64,  // Ensures cache correctness
}
```

### WASM Integration (`infera-wasm`)

Secure execution of custom policy logic using WebAssembly.

**Sandbox** (`src/sandbox.rs`):
- Wasmtime-based isolation
- Configurable resource limits:
  - Memory (default: 10MB)
  - CPU (fuel-based: 1M instructions)
  - Table elements
- Host functions available to WASM modules

**Host Functions** (`src/host.rs`):
- `log(ptr, len)` - Logging from WASM
- Execution context passed at invocation
- Safe memory access with bounds checking

### Replication (`infera-repl`)

Consistency management and replication infrastructure.

**Revision Tokens** (`src/token.rs`):
- Zookie-style tokens for snapshot consistency
- Vector clocks for causality tracking
- Base64-encoded JSON serialization
- Validation and causality checking

**Snapshot Reader** (`src/snapshot.rs`):
- Read-at-specific-revision support
- Blocking with timeout for unavailable revisions
- Enables linearizable reads

### Observability (`infera-observe`)

Metrics, tracing, and logging infrastructure.

**Features**:
- OpenTelemetry integration
- Prometheus metrics export
- Structured logging with tracing
- Request tracing across components

## Data Model

### Tuples

Authorization relationships are represented as tuples:

```rust
struct Tuple {
    object: String,      // "document:readme"
    relation: String,    // "viewer"
    user: String,        // "user:alice"
}
```

### Schema (IPL)

Policies are defined using IPL:

```ipl
type document {
    relation viewer
    relation editor
    relation owner

    relation can_view = viewer | editor | owner
    relation can_edit = editor | owner
    relation can_delete = owner
}

type folder {
    relation viewer
    relation parent: folder

    relation can_view = viewer | viewer from parent
}
```

## Request Flow

### Authorization Check

1. **Request arrives** at API layer (`/check` or `Check` RPC)
2. **Cache lookup** - Check if result is cached at current revision
3. **Query planning** - Optimizer analyzes relation and creates plan
4. **Evaluation** - Evaluator traverses relationship graph:
   - Lookup direct tuples in store
   - Recursively evaluate computed relations
   - Execute set operations (union/intersection/exclusion)
   - Invoke WASM modules if needed
5. **Cache result** - Store decision in cache with current revision
6. **Return decision** - Allow or Deny with optional trace

### Write Operation

1. **Request arrives** with tuples to write
2. **Store writes** tuples and returns new revision
3. **Cache invalidation** - Invalidate affected cache entries
4. **Return revision** - Client receives new revision token

## Performance Characteristics

### Latency Targets

- Simple checks (direct tuples): **<1ms**
- Complex checks (nested relations): **<10ms**
- Cache lookups: **<100μs**
- Writes (in-memory): **<1ms**

### Throughput

- Target: **100k+ checks/second** per instance
- Horizontal scaling via replication
- Cache hit rates typically >80%

### Resource Usage

- Memory: Proportional to tuple count and cache size
- CPU: Graph traversal and evaluation logic
- I/O: Minimal for in-memory, depends on store for FDB

## Concurrency Model

InferaDB is built on Tokio's async runtime:

- **Lock-free reads** where possible (RwLock for in-memory store)
- **Parallel evaluation** for union/intersection branches
- **Configurable concurrency** limits to prevent resource exhaustion
- **Non-blocking I/O** for all async operations

## Security Model

### WASM Sandbox

- Memory isolation per module execution
- CPU limits via fuel metering
- No file system or network access
- Host functions are the only I/O mechanism

### API Security

- Authentication/authorization for API endpoints (planned)
- Tenant isolation (planned)
- Rate limiting (planned)

## Deployment Topology

### Single-Node

```
┌─────────────────┐
│   InferaDB      │
│  (All-in-one)   │
│                 │
│  • API          │
│  • Evaluator    │
│  • Memory Store │
│  • Cache        │
└─────────────────┘
```

### Multi-Region (Planned)

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Region A    │    │  Region B    │    │  Region C    │
│              │◄──►│              │◄──►│              │
│  InferaDB    │    │  InferaDB    │    │  InferaDB    │
│  + FDB       │    │  + FDB       │    │  + FDB       │
└──────────────┘    └──────────────┘    └──────────────┘
       │                    │                    │
       └────────────────────┴────────────────────┘
                  Change Feed (NATS/Kafka)
```

## Design Principles

1. **Performance First** - Sub-10ms latency for most operations
2. **Correctness** - Revision-based consistency, no stale data
3. **Scalability** - Horizontal scaling via replication
4. **Flexibility** - WASM for custom logic, extensible via IPL
5. **Observability** - Complete tracing and metrics
6. **Safety** - Rust's type system, WASM sandboxing

## Trade-offs

### In-Memory Store
- **Pro**: Extremely fast (<1ms operations)
- **Con**: Limited by single-node memory, no persistence

### FoundationDB Store
- **Pro**: Distributed, durable, ACID transactions
- **Con**: Higher latency (~5-10ms), operational complexity

### Graph Evaluation
- **Pro**: Expressive, supports complex authorization models
- **Con**: Evaluation cost grows with graph depth

### Caching
- **Pro**: Massive performance improvement
- **Con**: Memory usage, invalidation complexity
