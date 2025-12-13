# InferaDB Server

Core policy engine for Relationship-Based Access Control (ReBAC). Handles IPL parsing, graph traversal, and authorization decisions.

## Quick Commands

```bash
# Testing
cargo nextest run --workspace          # All tests (preferred)
cargo test -p inferadb-engine-auth              # Specific crate
cargo test test_name                   # Single test

# Building & Quality
cargo build --release --workspace      # Release build
cargo +nightly fmt --all               # Format
cargo clippy --workspace --all-targets -- -D warnings  # Lint
make check                             # All quality checks

# Running
cargo watch -x 'run --bin inferadb-engine'  # Dev with auto-reload
make dev                                     # Or use make
```

## Architecture

### Layered Dependencies (flow downward only)

| Layer | Crates                                                                 | Purpose                               |
| ----- | ---------------------------------------------------------------------- | ------------------------------------- |
| 0     | `inferadb-engine-types`, `inferadb-engine-const`                       | Foundation types (zero internal deps) |
| 1     | `inferadb-engine-config`, `inferadb-engine-observe`                    | Configuration, telemetry              |
| 2     | `inferadb-engine-store`, `inferadb-engine-cache`                       | Storage abstraction, caching          |
| 3     | `inferadb-engine-wasm`, `inferadb-engine-core`, `inferadb-engine-auth` | Runtime, policy evaluation, auth      |
| 4     | `inferadb-engine-api`                                                  | API servers                           |
| 5     | `inferadb-engine`                                                      | Binary entry point                    |

### Key Crates

| Crate                   | Purpose                                                  |
| ----------------------- | -------------------------------------------------------- |
| `inferadb-engine-types` | Shared types: Relationship, Vault, Account, Decision     |
| `inferadb-engine-store` | Storage: MemoryBackend (dev), FoundationDBBackend (prod) |
| `inferadb-engine-cache` | Two-layer caching, vault-scoped                          |
| `inferadb-engine-core`  | IPL parser, graph traversal, decision engine             |
| `inferadb-engine-auth`  | JWT (EdDSA/RS256 only), OAuth 2.0                        |
| `inferadb-engine-api`   | REST (Axum) + gRPC (Tonic), service layer                |

## Critical Patterns

### 1. Multi-Tenancy (Vault-Scoped)

**All operations require vault parameter:**

```rust
// Storage - vault is always first parameter
async fn write(&self, vault: Uuid, relationships: Vec<Relationship>) -> Result<Revision>

// Handlers - extract from AuthContext
let vault = get_vault(&auth.0, state.default_vault);

// Services - pass vault through
state.evaluation_service.evaluate(vault, request).await?
```

### 2. Service Layer

Protocol-agnostic services separate business logic from REST/gRPC:

```rust
let decision = state.evaluation_service
    .evaluate(vault, core_request)
    .await?;
```

Services: `EvaluationService`, `ExpansionService`, `RelationshipService`, `ResourceService`, `SubjectService`, `WatchService`

### 3. Cache Invalidation

**Always invalidate after mutations:**

```rust
state.relationship_service
    .invalidate_cache_for_resources(&affected_resources)
    .await;
```

## Authentication

**Asymmetric algorithms only** (symmetric explicitly rejected):

- EdDSA (Ed25519)
- RS256, RS384, RS512

**JWT Claims:**

```rust
pub struct Claims {
    pub sub: String,
    pub vault: String,    // Required
    pub account: String,  // Required
    pub scopes: Vec<String>,
}
```

## Content Negotiation

Two response formats via `Accept` header:

- `application/json` (default)
- `text/toon` (30-60% token savings for LLMs)

```rust
pub async fn my_handler(
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
) -> Result<ResponseData<MyResponse>, ApiError> {
    Ok(ResponseData::new(response, format))
}
```

## Error Handling

```rust
#[derive(Debug, Error)]
pub enum MyError {
    #[error("Storage error")]
    Store(#[from] inferadb_engine_types::StoreError),
}
pub type Result<T> = std::result::Result<T, MyError>;
```

**Rules:**

- Use `thiserror::Error` derive
- Define `Result<T>` type alias
- Preserve chains with `#[from]` or `#[source]`
- Never stringify errors

## Configuration

**Precedence** (highest to lowest):

1. CLI args (`--port 8080`)
2. Env vars (`INFERADB__SERVER__PORT=8080`)
3. Config file (`config.yaml`)
4. Defaults

**Env format:** `INFERADB__` prefix, `__` separator

## Testing

```rust
#[tokio::test]
async fn test_vault_isolation() {
    let vault_a = Uuid::new_v4();
    let vault_b = Uuid::new_v4();

    store.write(vault_a, vec![rel]).await?;
    let results = store.read(vault_b, &key, Revision(0)).await?;
    assert!(results.is_empty(), "Vaults must be isolated");
}
```

**Organization:**

- Unit tests: `#[cfg(test)] mod tests` in source files
- Integration tests: `tests/` directory per crate
- Fixtures: `crates/inferadb-engine-test-fixtures`

## Development Patterns

### Adding API Endpoint

1. Define types in `inferadb-engine-types`
2. Add handler in `inferadb-engine-api/src/handlers/{resource}/`
3. Extract `AuthContext`, validate vault
4. Call service with vault parameter
5. Add integration tests

### Adding Storage Operation

1. Add method to `RelationshipStore` trait
2. Implement for `MemoryBackend`
3. Implement for `FoundationDBBackend` (if `fdb` feature)
4. Ensure vault-scoped
5. Add tests

### Adding Shared Type

1. Add to `inferadb-engine-types/src/mytype.rs`
2. Export from `inferadb-engine-types/src/lib.rs`
3. Re-export from original crate for compatibility

## Code Quality

- **Format:** `cargo +nightly fmt --all`
- **Lint:** `cargo clippy --workspace --all-targets -- -D warnings`
- **Audit:** `cargo audit && cargo deny check`
- **Tests:** `cargo nextest run --workspace`

All tests must pass. Fix bugs in code, not tests. Use `Result` and `thiserror` consistently.

## Security

- No symmetric JWT (HS256) - explicitly rejected
- Always validate vault ownership
- Enable replay protection in production
- Run `cargo audit` regularly
