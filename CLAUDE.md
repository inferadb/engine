# CLAUDE.md

This file provides quick-reference guidance for Claude Code when working in this repository.

Follow the directives outlined in AGENTS.md.

---

## Quick Commands

```bash
# Testing
cargo nextest run --workspace              # Run all tests (preferred)
cargo test -p infera-auth                  # Test specific crate
cargo test test_name                       # Run single test

# Building & Quality
cargo build --release --workspace          # Release build
cargo +nightly fmt --all                   # Format code
cargo clippy --workspace --all-targets -- -D warnings  # Lint
make check                                 # All quality checks

# Running Server
cargo watch -x 'run --bin inferadb-server' # Dev server with auto-reload
make dev                                   # Or use make
```

---

## Architecture Quick Reference

InferaDB is a **Relationship-Based Access Control (ReBAC)** authorization engine.

### Layered Architecture

```
Layer 0 (Foundation):  infera-types, infera-const
Layer 1 (Utilities):   infera-config, infera-observe
Layer 2 (Storage):     infera-store, infera-cache
Layer 3 (Runtime):     infera-wasm, infera-core, infera-auth
Layer 4 (Application): infera-repl, infera-api
Layer 5 (Binary):      infera-bin
```

**Critical Rules:**

- Dependencies flow **downward only**
- `infera-types` has **zero dependencies** on other internal crates
- Types used by multiple layers belong in the **lowest common layer**

### Core Crates

| Crate             | Purpose             | Key Features                                        |
| ----------------- | ------------------- | --------------------------------------------------- |
| **infera-types**  | Shared types        | Relationship, Vault, Account, Decision - zero deps  |
| **infera-config** | Configuration       | YAML files, env vars, CLI args                      |
| **infera-store**  | Storage abstraction | MemoryBackend (dev), FoundationDBBackend (prod)     |
| **infera-cache**  | Two-layer caching   | Authorization + expand caches, vault-scoped         |
| **infera-core**   | Policy evaluation   | IPL parser, graph traversal, decision engine        |
| **infera-wasm**   | WASM runtime        | WebAssembly policy modules via wasmtime             |
| **infera-auth**   | Authentication      | JWT (EdDSA/RS256 only), OAuth 2.0, vault validation |
| **infera-api**    | API servers         | REST (Axum) + gRPC (Tonic), service layer           |

**📖 Detailed architecture:** [docs/architecture.md](docs/architecture.md)

---

## Critical Patterns

### 1. Multi-Tenancy with Vaults

**All data operations are vault-scoped:**

```rust
// Storage operations ALWAYS take vault as first parameter
async fn write(&self, vault: Uuid, relationships: Vec<Relationship>) -> Result<Revision>

// Handlers extract vault from AuthContext
let vault = get_vault(&auth.0, state.default_vault);

// Services receive vault parameter
state.evaluation_service.evaluate(vault, request).await?
```

**Never skip vault validation.** See [MULTI_TENANCY.md](MULTI_TENANCY.md) for implementation status.

### 2. Service Layer Pattern

Services separate business logic from protocol adapters:

```rust
// Protocol-agnostic service call (works for gRPC, REST, AuthZEN)
let decision = state.evaluation_service
    .evaluate(vault, core_request)
    .await?;
```

**Available services:** EvaluationService, ExpansionService, RelationshipService, ResourceService, SubjectService, WatchService

### 3. Cache Invalidation

Handlers **must** invalidate cache after mutations:

```rust
// After writing relationships
state.relationship_service
    .invalidate_cache_for_resources(&affected_resources)
    .await;
```

**📖 Detailed patterns:** [docs/architecture.md](docs/architecture.md)

---

## Authentication Security

**Only asymmetric algorithms allowed:**

- EdDSA (Ed25519)
- RS256, RS384, RS512

Symmetric algorithms (HS256, etc.) are **explicitly rejected**.

**JWT Claims:**

```rust
pub struct Claims {
    pub sub: String,       // subject
    pub vault: String,     // Vault UUID (required)
    pub account: String,   // Account UUID (required)
    pub scopes: Vec<String>,
    // ... standard claims
}
```

**AuthContext includes vault and account for multi-tenant isolation.**

---

## Testing Guidelines

### Multi-Tenant Tests

Always create test vaults and verify isolation:

```rust
#[tokio::test]
async fn test_vault_isolation() {
    let vault_a = Uuid::new_v4();
    let vault_b = Uuid::new_v4();

    // Write to vault A
    store.write(vault_a, vec![rel_a]).await?;

    // Verify vault B cannot see vault A's data
    let results = store.read(vault_b, &key, Revision(0)).await?;
    assert!(results.is_empty(), "Vaults must be isolated");
}
```

### Test Organization

- **Unit tests:** `#[cfg(test)] mod tests` within source files
- **Integration tests:** `tests/` directory of each crate
- **Fixtures:** `crates/infera-test-fixtures` for shared utilities

---

## Common Development Patterns

### Adding a New API Endpoint

1. Define request/response types in `infera-types`
2. Add handler in `infera-api/src/handlers/{resource}/`
3. Extract `AuthContext` and validate vault access
4. Call service from `AppState` with vault parameter
5. Add integration tests in `infera-api/tests/`

**📖 Handler organization:** [docs/architecture.md](docs/architecture.md#handler-organization)

### Content Negotiation & Response Formats

InferaDB REST APIs support two response formats via the `Accept` header:

1. **JSON (default):** `application/json`
2. **TOON:** `text/toon` (Token Oriented Object Notation for LLM optimization - saves 30-60% tokens)

**Handler Pattern:**

```rust
use crate::content_negotiation::{AcceptHeader, ResponseData};

pub async fn my_handler(
    auth: OptionalAuth,
    AcceptHeader(format): AcceptHeader,  // Extract format preference
    State(state): State<AppState>,
) -> Result<ResponseData<MyResponse>, ApiError> {
    // ... business logic ...
    Ok(ResponseData::new(response, format))  // Serializes based on format
}
```

**Usage:**

```bash
# JSON response (default)
curl https://api/v1/vaults

# TOON response (30-60% token savings)
curl -H "Accept: text/toon" https://api/v1/vaults
```

**Streaming Endpoints (JSON-only):**

Streaming endpoints (SSE) only support JSON. Reject TOON requests:

```rust
pub async fn stream_handler(
    auth: OptionalAuth,
    AcceptHeader(format): AcceptHeader,
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<...>>, ApiError> {
    // Streaming endpoints only support JSON
    if format == ResponseFormat::Toon {
        return Err(ApiError::InvalidRequest(
            "Streaming endpoints do not support TOON format".to_string()
        ));
    }
    // ... streaming logic ...
}
```

**📖 Complete TOON guide:** [api/content-negotiation.md](api/content-negotiation.md)

### Adding New Storage Operations

1. Add method to `RelationshipStore` trait in `infera-store/src/lib.rs`
2. Implement for `MemoryBackend` in `infera-store/src/memory.rs`
3. Implement for `FoundationDBBackend` if using `fdb` feature
4. Ensure all operations are vault-scoped
5. Add tests

### Adding a New Type

**If used by multiple crates:**

1. Add to `infera-types/src/mytype.rs`
2. Export from `infera-types/src/lib.rs`
3. Re-export from original crate for compatibility

**📖 Type organization:** [docs/TYPE_ORGANIZATION.md](docs/TYPE_ORGANIZATION.md)

---

## Error Handling

**Every error enum MUST:**

1. Use `thiserror::Error` derive
2. Have a Result type alias: `pub type Result<T> = std::result::Result<T, MyError>;`
3. Preserve error chains with `#[from]` or `#[source]`

```rust
#[derive(Debug, Error)]
pub enum MyError {
    #[error("Storage error")]
    Store(#[from] infera_types::StoreError),  // Auto-implements From<>
}

pub type Result<T> = std::result::Result<T, MyError>;
```

**Never stringify errors** - it breaks the error chain.

**📖 Complete guide:** [docs/ERROR_HANDLING.md](docs/ERROR_HANDLING.md)

---

## Configuration

**Precedence (highest to lowest):**

1. Command-line arguments (`--port 8080`)
2. Environment variables (`INFERADB__SERVER__PORT=8080`)
3. Configuration file (`config.yaml`)
4. Default values

**Environment variable format:** Use `INFERADB__` prefix and `__` separator.

---

## Security Notes

- Never use symmetric JWT algorithms (HS256) - explicitly rejected
- Always validate vault ownership before operations
- Enable replay protection in production
- Follow least-privilege principle for scopes
- Regularly run: `cargo audit`

---

## Troubleshooting

**Vault errors:**

- Check `Relationship.vault` is set
- Ensure `AuthContext` includes vault/account
- Verify storage operations receive vault parameter

**Auth errors:**

- Verify asymmetric algorithm (EdDSA/RS256)
- Check token includes vault/account claims
- Ensure JWKS URL is accessible

**Build errors:**

- Run `cargo clean`
- Check Rust version: `rustc --version` (need 1.83+)
- Run `cargo update`

---

## CI/CD Pipeline

**5 Workflows:**

- `ci.yml` - Main CI (format, lint, build, test, coverage)
- `security.yml` - Security audits (cargo-audit, cargo-deny)
- `benchmark.yml` - Performance regression detection
- `release.yml` - Automated releases (binaries, Docker, SBOM, provenance)
- `dependency-review.yml` - Dependency vulnerability scanning

**Run tests locally like CI:**

```bash
cargo nextest run --workspace --profile ci
cargo test --workspace --doc
cargo audit
cargo deny check
```
