# Developer Documentation

Welcome to the InferaDB developer documentation! This guide will help you understand the codebase, contribute effectively, and maintain code quality.

## Quick Links

- [Building from Source](../guides/building.md) - Development setup and build instructions
- [Testing Guide](../guides/testing.md) - Comprehensive testing documentation
- [Architecture Overview](../architecture.md) - System design and components
- [Contributing Guide](../../CONTRIBUTING.md) - How to contribute to InferaDB
- [API Documentation (Rustdoc)](#rustdoc-documentation) - Generated code documentation

## Table of Contents

- [Getting Started](#getting-started)
- [Codebase Structure](#codebase-structure)
- [Development Workflow](#development-workflow)
- [Code Style and Standards](#code-style-and-standards)
- [Rustdoc Documentation](#rustdoc-documentation)
- [Internal APIs](#internal-apis)
- [Extension Points](#extension-points)
- [Common Tasks](#common-tasks)
- [Debugging Tips](#debugging-tips)
- [Performance Optimization](#performance-optimization)

## Getting Started

### Prerequisites

- Rust 1.78+ (via rustup)
- [Mise](https://mise.jdx.dev/) for task automation
- Git for version control

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/inferadb/server
cd server

# Trust mise configuration
mise trust

# Install dependencies
mise install

# Run tests to verify setup
mise run test
```

See [Building from Source](../guides/building.md) for detailed setup instructions.

## Codebase Structure

InferaDB is organized as a Rust workspace with multiple crates:

```text
server/
├── crates/
│   ├── inferadb-api/       # REST + gRPC API layer
│   ├── inferadb-auth/      # Authentication & authorization
│   ├── inferadb-cache/     # Result caching
│   ├── inferadb-config/    # Configuration management
│   ├── inferadb-core/      # Policy evaluation engine (the heart)
│   ├── inferadb-observe/   # Metrics, tracing, logging
│   ├── inferadb-repl/      # Replication & consistency
│   ├── inferadb-store/     # Storage abstraction
│   ├── inferadb-wasm/      # WASM policy modules
│   └── inferadb-bin/       # Binary entry point
├── docs/                 # Documentation
├── api/                  # API documentation (OpenAPI, Swagger UI)
├── tests/                # End-to-end tests
├── scripts/              # Build and development scripts
├── k8s/                  # Kubernetes manifests
├── helm/                 # Helm chart
├── terraform/            # Infrastructure as Code
├── grafana/              # Grafana dashboards
└── prometheus/           # Prometheus alerting rules
```

### Crate Dependency Graph

```text
inferadb-bin
    ├── inferadb-api
    │   ├── inferadb-auth
    │   ├── inferadb-core
    │   └── inferadb-observe
    ├── inferadb-core
    │   ├── inferadb-cache
    │   ├── inferadb-store
    │   ├── inferadb-wasm
    │   └── inferadb-observe
    ├── inferadb-repl
    │   ├── inferadb-store
    │   └── inferadb-observe
    └── inferadb-config
```

### Key Modules

#### inferadb-core

The evaluation engine - the heart of InferaDB:

- `evaluator.rs` - Main policy evaluation logic
- `graph.rs` - Graph traversal for authorization checks
- `ipl.rs` - IPL (Infera Policy Language) parser
- `types.rs` - Core data structures (Tuple, Schema, etc.)
- `trace.rs` - Decision tracing for debugging

#### inferadb-store

Storage abstraction with multiple backends:

- `lib.rs` - TupleStore trait definition
- `memory.rs` - In-memory backend (development)
- `foundationdb.rs` - FoundationDB backend (production)
- `factory.rs` - Backend selection and initialization

#### inferadb-auth

Authentication and authorization:

- `jwt.rs` - JWT validation (Private-Key, OAuth, Internal)
- `jwks_cache.rs` - JWKS caching with stale-while-revalidate
- `oauth.rs` - OAuth 2.0 integration
- `middleware.rs` - gRPC/REST authentication middleware
- `replay.rs` - Replay attack protection

#### inferadb-api

API layer with REST and gRPC:

- `lib.rs` - REST API endpoints (Axum)
- `grpc.rs` - gRPC service implementation (Tonic)
- `proto/infera.proto` - Protocol buffer definitions

## Development Workflow

### Daily Development

```bash
# Use standard cargo commands
cargo test                              # Run tests
cargo build                             # Build debug
cargo build --release                   # Build release
cargo clippy --workspace -- -D warnings # Lint
cargo fmt                               # Format

# Or use Make shortcuts
make test        # Run all tests
make check       # Run all checks
make dev         # Start dev server with watch
make help        # Show all commands
```

### Before Committing

```bash
# Ensure everything passes
make check       # fmt + clippy + test + audit

# Or individually
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo audit
cargo deny check

# Generate documentation
./scripts/generate-docs.sh
```

### Code Quality Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass (`cargo test --all`)
- [ ] `cargo fmt` has been run
- [ ] `cargo clippy` passes with no warnings
- [ ] New features have tests
- [ ] Public APIs have Rustdoc comments
- [ ] CHANGELOG.md updated (if applicable)

## Code Style and Standards

### Rust Style

We follow standard Rust conventions enforced by `rustfmt` and `clippy`:

```rust
// Good: Descriptive names, clear types
pub fn check_permission(
    subject: &str,
    resource: &str,
    permission: &str,
) -> Result<Decision, EvalError> {
    // Implementation
}

// Bad: Cryptic names, unclear intent
pub fn chk(s: &str, r: &str, p: &str) -> Result<D, E> {
    // Implementation
}
```

### Error Handling

Use `Result` types and `thiserror` for custom errors:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("tuple not found: {0}")]
    NotFound(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(#[source] std::io::Error),
}
```

### Async Code

Use Tokio for async runtime:

```rust
#[tokio::test]
async fn test_async_operation() {
    let result = some_async_fn().await;
    assert!(result.is_ok());
}
```

### Performance Considerations

- Avoid unnecessary allocations
- Use `&str` instead of `String` when possible
- Prefer `Vec` over `LinkedList`
- Use `Arc` for shared ownership, avoid `Rc` in async code
- Profile before optimizing

## Rustdoc Documentation

### Generating Documentation

Generate Rustdoc for all crates:

```bash
# Generate documentation
./scripts/generate-docs.sh

# Open in browser
open target/doc/inferadb/index.html  # macOS
xdg-open target/doc/inferadb/index.html  # Linux
```

### Writing Documentation

Every public item must have documentation:

````rust
/// Checks if a subject has permission on a resource.
///
/// This is the primary authorization check method. It evaluates
/// the policy graph and returns an allow/deny decision.
///
/// # Arguments
///
/// * `subject` - The user or entity requesting access (e.g., "user:alice")
/// * `resource` - The resource being accessed (e.g., "document:readme")
/// * `permission` - The permission being checked (e.g., "viewer")
///
/// # Returns
///
/// Returns `Ok(Decision::Allow)` if access is granted, `Ok(Decision::Deny)`
/// if denied, or an error if evaluation fails.
///
/// # Examples
///
/// ```
/// use inferadb::check_permission;
///
/// let decision = check_permission("user:alice", "doc:readme", "viewer")?;
/// assert_eq!(decision, Decision::Allow);
/// ```
///
/// # Errors
///
/// Returns `EvalError` if:
/// - The schema is invalid
/// - The storage backend fails
/// - The policy graph contains cycles
pub async fn check_permission(
    subject: &str,
    resource: &str,
    permission: &str,
) -> Result<Decision, EvalError> {
    // Implementation
}
````

### Documentation Best Practices

- Start with a one-line summary
- Explain **what** the function does, not **how**
- Document all parameters with `# Arguments`
- Document return values with `# Returns`
- Document errors with `# Errors`
- Include examples with `# Examples`
- Use code blocks with the `rust` language tag
- Link to related items using `[ItemName]` syntax

## Internal APIs

### Core Evaluation API

The main evaluation API is in `inferadb-core`:

```rust
use inferadb_core::{Evaluator, Schema, Tuple};

// Create evaluator
let evaluator = Evaluator::new(store, cache, schema);

// Check permission
let decision = evaluator.check(subject, resource, permission).await?;

// Check with trace (for debugging)
let (decision, trace) = evaluator.check_with_trace(subject, resource, permission).await?;

// Expand relation
let response = evaluator.expand(resource, relation, limit, offset).await?;
```

### Storage API

The storage abstraction is in `inferadb-store`:

```rust
use inferadb_store::{TupleStore, StorageFactory, StorageConfig};

// Create storage backend
let config = StorageConfig::default();
let store = StorageFactory::create(config).await?;

// Write tuples
store.write(&[tuple1, tuple2]).await?;

// Read tuples
let tuples = store.read(object, relation, user).await?;

// Delete tuples
store.delete(&[tuple1]).await?;
```

### Caching API

The cache is in `inferadb-cache`:

```rust
use inferadb_cache::Cache;

// Create cache
let cache = Cache::new(10000, Duration::from_secs(300));

// Check cache
if let Some(decision) = cache.get(&key) {
    return Ok(decision);
}

// Store result
cache.insert(key, decision);

// Invalidate
cache.invalidate_before(revision);
```

## Extension Points

InferaDB is designed to be extensible:

### 1. Storage Backends

Implement the `TupleStore` trait to add new storage backends:

```rust
#[async_trait]
pub trait TupleStore: Send + Sync {
    async fn read(&self, ...) -> Result<Vec<Tuple>>;
    async fn write(&self, tuples: &[Tuple]) -> Result<u64>;
    async fn delete(&self, tuples: &[Tuple]) -> Result<u64>;
    async fn current_revision(&self) -> Result<u64>;
}
```

See [storage/memory.rs](../../crates/inferadb-store/src/memory.rs) for an example.

### 2. WASM Policy Modules

Create custom policy modules in WASM:

```wat
(module
  (func (export "check") (param i32 i32 i32) (result i32)
    ;; Custom authorization logic
    (i32.const 1) ;; Return 1 for allow, 0 for deny
  )
)
```

See [WASM Integration Guide](../advanced/wasm.md) for details.

### 3. Authentication Methods

Add new authentication methods by implementing JWT validation:

```rust
impl AuthValidator {
    pub async fn validate_custom(&self, token: &str) -> Result<AuthContext> {
        // Custom validation logic
    }
}
```

### 4. Secret Providers

Implement custom secret providers:

```rust
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn get_secret(&self, name: &str) -> Result<String, ConfigError>;
}
```

## Common Tasks

### Adding a New Endpoint

1. Define the endpoint in `crates/inferadb-api/src/lib.rs`:

```rust
async fn new_endpoint(
    State(evaluator): State<Arc<Evaluator>>,
    Json(request): Json<NewRequest>,
) -> Result<Json<NewResponse>, ApiError> {
    // Implementation
}
```

1. Register the route:

```rust
let app = Router::new()
    .route("/new", post(new_endpoint))
    .with_state(evaluator);
```

1. Add tests in `crates/inferadb-api/tests/`:

```rust
#[tokio::test]
async fn test_new_endpoint() {
    // Test implementation
}
```

### Adding a New Metric

1. Define the metric in `crates/inferadb-observe/src/metrics.rs`:

```rust
pub fn record_new_metric(value: f64, labels: &[(&str, &str)]) {
    histogram!("inferadb_new_metric_seconds", labels).record(value);
}
```

1. Initialize in `init_metrics_descriptions()`:

```rust
describe_histogram!(
    "inferadb_new_metric_seconds",
    Unit::Seconds,
    "Description of what this metric measures"
);
```

1. Use in your code:

```rust
use inferadb_observe::record_new_metric;

let start = Instant::now();
// ... operation ...
record_new_metric(start.elapsed().as_secs_f64(), &[("label", "value")]);
```

### Adding a New Test Scenario

1. Create a new test file in `crates/inferadb-core/tests/`:

```rust
mod common;

use common::*;

#[tokio::test]
async fn test_new_scenario() {
    let fixture = TestFixture::new().await;

    // Setup schema and tuples
    fixture.write_tuple("user:alice", "doc:1", "viewer").await;

    // Test assertions
    assert_allowed(&fixture, "user:alice", "doc:1", "viewer").await;
}
```

## Debugging Tips

### Enable Debug Logging

```bash
# Set log level
RUST_LOG=debug cargo run

# Specific module
RUST_LOG=inferadb_core=debug cargo run

# Multiple modules
RUST_LOG=inferadb_core=debug,inferadb_store=trace cargo run
```

### Use Decision Traces

```rust
// Get detailed trace
let (decision, trace) = evaluator.check_with_trace(
    "user:alice",
    "doc:1",
    "viewer"
).await?;

println!("Decision: {:?}", decision);
println!("Trace: {:#?}", trace);
```

### Profiling

```bash
# CPU profiling with cargo-flamegraph
cargo flamegraph --bin inferadb

# Memory profiling with valgrind
valgrind --tool=massif target/release/inferadb

# Benchmarking
cargo bench
```

### Common Issues

**Issue**: Tests fail with "address already in use"
**Solution**: Kill existing server instances or use different ports

**Issue**: FoundationDB tests fail
**Solution**: Tests require FDB cluster. Run with `--features fdb` only if FDB is available

**Issue**: WASM tests fail
**Solution**: Ensure `wat` crate is available (dev-dependency)

## Performance Optimization

### Benchmarking

Run benchmarks before and after changes:

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench evaluator

# Save baseline
cargo bench -- --save-baseline before

# Compare
cargo bench -- --baseline before
```

### Profiling Tools

- **cargo-flamegraph**: CPU profiling with flame graphs
- **criterion**: Statistical benchmarking
- **valgrind**: Memory profiling
- **perf**: Linux performance analysis

### Optimization Guidelines

1. **Measure first**: Always profile before optimizing
2. **Focus on hot paths**: Optimize the 20% of code that runs 80% of the time
3. **Avoid premature optimization**: Clarity > premature optimization
4. **Use benchmarks**: Verify improvements with benchmarks
5. **Document tradeoffs**: Explain why optimizations were made

### Common Optimizations

- Use `&str` instead of `String` for read-only data
- Batch operations instead of single operations
- Cache expensive computations
- Use `Arc` for shared data instead of cloning
- Avoid unnecessary allocations
- Use `Vec::with_capacity` when size is known

## Additional Resources

- [Rust Book](https://doc.rust-lang.org/book/) - Learn Rust
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) - API design
- [Rust Performance Book](https://nnethercote.github.io/perf-book/) - Performance optimization
- [Async Book](https://rust-lang.github.io/async-book/) - Async programming in Rust
- [InferaDB Architecture](../architecture.md) - System architecture
- [InferaDB Testing Guide](../guides/testing.md) - Testing best practices

## Getting Help

- **Documentation**: Browse [docs/](../)
- **Code Documentation**: Run `./scripts/generate-docs.sh`
- **Issues**: [GitHub Issues](https://github.com/inferadb/server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/inferadb/server/discussions)

---

**Ready to contribute?** Check out [CONTRIBUTING.md](../../CONTRIBUTING.md) for the contribution workflow!
