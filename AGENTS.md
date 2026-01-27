# CLAUDE.md

InferaDB Engine: ReBAC authorization engine with graph traversal, policy evaluation, and sub-millisecond latency. Rust 1.92 (2024 edition), REST + gRPC API.

## Critical Constraints

**These rules are non-negotiable:**

- No `unsafe` code
- No `.unwrap()` — use `.context()` or `?`
- No `panic!`, `todo!()`, `unimplemented!()`
- No placeholder stubs — fully implement or don't write
- No TODO/FIXME/HACK comments
- No backwards compatibility shims or feature flags
- Write tests before implementation, target 90%+ coverage

## Commands

```bash
# Development (preferred)
just test                      # standard tests (~30s)
just test-fast                 # quick validation (~15s)
just test-full                 # comprehensive (~5min)
just lint                      # clippy
just fmt                       # format

# Manual
cargo build --workspace
cargo test -p inferadb-engine-core
cargo +nightly fmt
cargo clippy --workspace --all-targets -- -D warnings

# Run server
cargo run --bin inferadb-engine
```

## Architecture

```
REST/gRPC API (inferadb-engine-api)
       ↓
inferadb-engine-core    — IPL parser, graph traversal, permission evaluation
       ↓
inferadb-engine-repository — Domain repositories (relationships, vaults, orgs)
       ↓
inferadb-storage        — Backend abstraction (Memory | Ledger)
```

**Crates:**

- `engine` — Binary entrypoint, server bootstrap
- `api` — Axum REST handlers, tonic gRPC services, middleware
- `core` — Evaluator, IPL parser, optimizer, graph algorithms
- `auth` — JWT validation, JWKS, OAuth, signing key cache
- `repository` — EngineStorage, relationship/vault/org repositories
- `store` — InferaStore trait, factory, metrics
- `cache` — Moka-based result caching
- `config` — YAML/env configuration, secrets, hot reload
- `types` — Shared types, request/response builders
- `observe` — Tracing, metrics, structured logging
- `wasm` — Wasmtime sandbox for custom policy logic

**Key types:**

- `Evaluator` (core/evaluator/) — Permission check, expand, list operations
- `EngineStorage` (repository/storage.rs) — Unified store implementing all traits
- `ServiceContext` (api/services/) — Shared context for API handlers

**Data model:**

- Organization → tenant isolation boundary
- Vault → relationship store within organization
- Relationship → authorization tuple (resource, relation, subject)
- IPL Schema → type definitions and computed relations

## Error Handling

Use `thiserror` for error types. Propagate with `?`.

```rust
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Store error: {0}")]
    Store(#[from] StoreError),

    #[error("Not found: {0}")]
    NotFound(String),
}
```

## Builder Pattern (bon)

Use `bon` for type-safe builders:

```rust
#[derive(bon::Builder)]
struct Config {
    #[builder(default = 100)]
    max_connections: u32,
    #[builder(into)]
    name: String,
}

let config = Config::builder().name("test").build();
```

## Testing

**Test tiers:**

| Command | Use Case |
|---------|----------|
| `just test-fast` | PR checks, pre-commit (~15s) |
| `just test` | Standard CI (~30s) |
| `just test-full` | Nightly, release validation (~5min) |

**Guidelines:**

- Use `inferadb_engine_test_fixtures` for shared utilities
- Property tests: use `proptest_config()` for tier-aware case counts
- Gate expensive tests behind `#[cfg(feature = "test-full")]`
- Mark slow tests (>1s) with `#[ignore]`

## Code Quality

**Linting:** `cargo clippy --workspace --all-targets -- -D warnings`

**Formatting:** `cargo +nightly fmt`

**Doc comments:** Use ` ```no_run ` for examples — skipped by `cargo test`, validated by `cargo doc`.
