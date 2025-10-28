## **1. Architectural Overview**

Think of the InferaDB server as a **layered, modular service**:

```plaintext
┌────────────────────────────────────────────────────┐
│                      API Layer                     │
│ REST/gRPC endpoints (AuthZEN-compatible)           │
│ Tuple reads/writes, check/expand/simulate/explain  │
└────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────┐
│                 Evaluation Engine                  │
│ - IPL parser + interpreter                         │
│ - Policy graph traversal                            │
│ - WASM module host                                 │
│ - Decision tracing + caching                       │
└────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────┐
│                 Data Access Layer                  │
│ - Tuple store abstraction (FoundationDB/Cockroach) │
│ - Snapshot isolation + revision tokens             │
│ - Event streaming (NATS/Kafka)                     │
└────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────┐
│               Replication & Consistency            │
│ - Change feed + vector clocks                      │
│ - Causal ordering enforcement                      │
│ - Conflict resolution + merges                     │
└────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────┐
│                   Core Infrastructure              │
│ - Async runtime (Tokio)                            │
│ - Configuration + observability                    │
│ - Caching layer (in-memory + Redis)                │
│ - Metrics + Tracing + Logging                      │
└────────────────────────────────────────────────────┘
```

Each layer is separated into a crate for testability and replacement flexibility.

---

## **2. Recommended Crate Layout**

Use a **workspace-based structure** to keep boundaries clear.

```plaintext
server/
├── Cargo.toml
├── crates/
│   ├── infera-core/              # Evaluation engine and IPL interpreter
│   ├── infera-store/             # Storage abstraction and backend connectors
│   ├── infera-wasm/              # WASM runtime host and sandbox interface
│   ├── infera-repl/              # Replication, consistency, and revision tokens
│   ├── infera-api/               # REST/gRPC handlers (AuthZEN)
│   ├── infera-cache/             # Caching layer and computed usersets
│   ├── infera-observe/           # Telemetry, tracing, metrics, logging
│   ├── infera-config/            # Configuration loader and schema validation
│   └── infera-bin/               # The actual server binary entrypoint
│
└── tests/
    ├── integration/
    ├── performance/
    └── regression/
```

Each `inferadb-*` crate builds toward **composability** and **reusability** — you’ll be able to export some (like `infera-core` or `infera-wasm`) as libraries for SDKs or embedded PDP use cases.

---

## **3. Module Responsibilities**

### **`infera-core`**

**Purpose:** Core reasoning and policy evaluation engine.

- IPL (Infera Policy Language) parser and evaluator

  - Use [`pest`](https://pest.rs) or [`nom`](https://docs.rs/nom) for parsing.

- Relationship graph traversal

  - Backed by tuple store abstraction layer.

- Decision evaluation pipeline:

  - Permission → relation expansion → tuple reads → module invocation → result.

- Deterministic decision tree + explain output.
- Unit-tested for each stage.

```rust
pub struct Evaluator {
    store: Arc<dyn TupleStore>,
    wasm_host: Option<Arc<WasmHost>>,
}

impl Evaluator {
    pub async fn check(&self, request: CheckRequest) -> Result<Decision, EvalError> { ... }
    pub async fn expand(&self, request: ExpandRequest) -> Result<UsersetTree, EvalError> { ... }
}
```

---

### **`infera-store`**

**Purpose:** Abstract database operations and maintain revision consistency.

- `TupleStore` trait with backends:

  - `FoundationDBBackend`
  - `CockroachBackend`
  - `MemoryBackend` (for tests)

- Revision snapshot manager.
- Change feed → publish events for replication layer.
- Transactional write batching.

```rust
#[async_trait]
pub trait TupleStore {
    async fn read(&self, key: &TupleKey, revision: Revision) -> Result<Vec<Tuple>, StoreError>;
    async fn write(&self, tuples: Vec<Tuple>) -> Result<Revision, StoreError>;
    async fn get_revision(&self) -> Result<Revision, StoreError>;
}
```

---

### **`infera-wasm`**

**Purpose:** Host sandboxed WASM policy modules.

- Integrates with [`wasmtime`](https://crates.io/crates/wasmtime) or [`wasmer`] for execution.
- Exposes deterministic host API (read-only access to resource/subject/context).
- Handles:

  - Module loading and signature validation.
  - Memory and CPU quotas.
  - Version pinning.
  - Execution metrics.

```rust
pub struct WasmHost {
    engine: wasmtime::Engine,
    store: wasmtime::Store<()>,
    modules: RwLock<HashMap<String, WasmModule>>,
}

impl WasmHost {
    pub fn execute(&self, module: &str, func: &str, args: &[Value]) -> Result<Value, WasmError> { ... }
}
```

---

### **`infera-repl`**

**Purpose:** Replication and consistency management.

- Implements **revision tokens** (`zookie`-style snapshots).
- Handles replication and merging between PDP cells.
- Provides consistent event publishing for eventual replication.
- CRDT-inspired change model for conflict-free merges.

---

### **`infera-api`**

**Purpose:** Expose gRPC and REST APIs (AuthZEN + Infera-native).

- Uses [`axum`](https://docs.rs/axum) or [`tonic`](https://github.com/hyperium/tonic).
- Endpoints:

  - `POST /check`
  - `POST /expand`
  - `POST /write`
  - `POST /simulate`
  - `POST /explain`

- Includes middleware for:

  - Request tracing (`OpenTelemetry`)
  - Auth (tenant tokens)
  - Rate limiting

- Marshals results from `infera-core` and `infera-store`.

---

### **`infera-cache`**

**Purpose:** Optimize common queries with deterministic caching.

- Cache computed usersets, tuple lookups, and expansion results.
- Configurable time-to-live or revision-based invalidation.
- Use `moka` (fast async cache) or Redis integration.

---

### **`infera-observe`**

**Purpose:** Centralized observability layer.

- Distributed tracing (OpenTelemetry)
- Metrics (Prometheus exporter)
- Structured logging (tracing crate)
- Decision latency histogram, WASM execution metrics, cache hit ratio.

---

### **`infera-config`**

**Purpose:** Configuration management and environment injection.

- Load `.env`, YAML, or JSON configuration.
- Merge CLI args, env vars, and file settings.
- Validate configuration structure at startup.

---

### **`infera-bin`**

**Purpose:** The binary entrypoint.

```rust
#[tokio::main]
async fn main() -> Result<()> {
    infera_observe::init_tracing();
    let config = infera_config::load("config.yaml")?;
    let store = infera_store::foundationdb::connect(config.store)?;
    let wasm_host = infera_wasm::WasmHost::new(config.wasm)?;
    let evaluator = infera_core::Evaluator::new(store, wasm_host);
    infera_api::serve(evaluator, config).await
}
```

---

## **4. Async & Concurrency Model**

- **Runtime:** [Tokio](https://tokio.rs) — proven for async I/O and actor-like concurrency.
- **Database:** Asynchronous driver with per-request snapshot.
- **Evaluation:** Parallel traversal of sub-relations (futures combinators).
- **WASM:** Run in-thread per request, but pool engine contexts to avoid reinitialization.

Target concurrency model:

```plaintext
- 1 thread pool for I/O (Tokio)
- 1 bounded thread pool for WASM execution
- 1 background task for replication + event handling
```

---

## **5. Testing Strategy**

| Level       | Type                   | Description                                             |
| ----------- | ---------------------- | ------------------------------------------------------- |
| Unit        | Crate-level            | Core logic: IPL parsing, tuple traversal, WASM sandbox. |
| Integration | End-to-end             | Simulate real authorization graph.                      |
| Load        | Performance benchmarks | Sustained throughput under 100k+ RPS.                   |
| Consistency | Revision-based         | Ensure snapshot correctness under concurrent writes.    |
| Security    | Sandbox validation     | Validate WASM isolation and determinism.                |

Use [`criterion`](https://docs.rs/criterion) for microbenchmarks and [`proptest`](https://docs.rs/proptest) for randomized testing of policy graphs.

---

## **6. Observability and Dev Ergonomics**

- **Tracing:** `tracing` crate with span hierarchy for each check.
- **Metrics:** Export via `/metrics` endpoint in Prometheus format.
- **Explainability:** Trace tree for each check (for dashboard visualization).
- **Config Reloading:** Hot-reloadable configuration with SIGHUP or REST endpoint.

---

## **7. Build and CI/CD Recommendations**

| Stage                | Tool                                | Purpose                                |
| -------------------- | ----------------------------------- | -------------------------------------- |
| **Linting**          | `clippy`, `cargo fmt`, `cargo deny` | Code hygiene and dependency audit.     |
| **Testing**          | `cargo test --workspace`            | Full test suite execution.             |
| **Benchmarking**     | `cargo bench`                       | Continuous performance tracking.       |
| **Security**         | `cargo audit`                       | Vulnerability scanning.                |
| **CI/CD**            | GitHub Actions                      | Build, test, and publish Docker image. |
| **Containerization** | Multi-stage Docker build            | Produce minimal Alpine-based images.   |

---

## **8. Example Workspace Configuration**

`server/Cargo.toml`

```toml
[workspace]
members = [
    "crates/infera-core",
    "crates/infera-store",
    "crates/infera-wasm",
    "crates/infera-repl",
    "crates/infera-api",
    "crates/infera-cache",
    "crates/infera-observe",
    "crates/infera-config",
    "crates/infera-bin"
]
```

---

## **9. Summary**

| Goal              | Design Decision                                                        |
| ----------------- | ---------------------------------------------------------------------- |
| **Modularity**    | Each major subsystem as its own crate.                                 |
| **Safety**        | Rust ownership, traits, and async enforcement prevent race conditions. |
| **Performance**   | Tokio runtime + direct WASM hosting keep latency low.                  |
| **Testability**   | Workspace-level testing with memory backends.                          |
| **Extensibility** | Independent crates can evolve or be reused externally.                 |
| **Auditability**  | Decision tracing and strong logging built into every layer.            |
