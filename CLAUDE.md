# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Follow the directives outlined in AGENTS.md.

---

## Development Commands

### Testing

```bash
# Run all tests (preferred - uses nextest for faster parallel execution)
cargo nextest run --workspace

# Run tests for a specific crate
cargo test -p infera-auth

# Run a single test by name
cargo test test_vault_validation_with_valid_vault

# Run tests with output
cargo test -- --nocapture
```

### Building & Code Quality

```bash
# Build debug/release binary
cargo build
cargo build --release --workspace

# Format code
cargo +nightly fmt --all

# Run clippy linter
cargo clippy --workspace --all-targets -- -D warnings

# Auto-fix clippy warnings
cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged

# Run all quality checks
make check
```

### Running the Server

```bash
# Development server with auto-reload
cargo watch -x 'run --bin inferadb'

# Or using make
make dev
```

---

## Architecture Overview

InferaDB is a **Relationship-Based Access Control (ReBAC)** authorization engine built as a modular Rust workspace.

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
- Dependencies flow **downward only** (higher layers depend on lower layers, never reverse)
- `infera-types` has **zero dependencies** on other internal crates
- If a type is needed by multiple layers, it belongs in the **lowest common layer**

### Core Crates

1. **infera-types**: Shared type definitions (Relationship, Vault, Account, Decision, etc.). Zero dependencies.
2. **infera-const**: Compile-time constants and limits.
3. **infera-config**: Configuration management (YAML, env vars, CLI args).
4. **infera-observe**: Observability - metrics (Prometheus), tracing (OpenTelemetry).
5. **infera-cache**: Two-layer caching (authorization results + expand trees). Uses `moka`.
6. **infera-store**: Storage abstraction (`RelationshipStore`, `VaultStore`, `AccountStore`).
   - `MemoryBackend` - In-memory HashMap (dev/testing)
   - `FoundationDBBackend` - Distributed storage (production)
7. **infera-core**: Policy evaluation engine (IPL parser, graph traversal, decision evaluation).
8. **infera-wasm**: WebAssembly policy module runtime using `wasmtime`.
9. **infera-repl**: Multi-region replication with conflict resolution.
10. **infera-auth**: Authentication/authorization (Layer 3):
    - JWT validation (EdDSA, RS256 only - no symmetric algorithms)
    - OAuth 2.0 Bearer token support
    - Basic vault validation (nil checks, AuthContext extraction)
    - **Note:** Does NOT depend on storage/cache layers (Layer 2)
11. **infera-api**: HTTP and gRPC API servers (Axum + Tonic):
    - Service layer (EvaluationService, ExpansionService, RelationshipService, etc.)
    - Rate limiting, health checks
12. **infera-bin**: Main binary entry point.
13. **infera-test-fixtures**: Shared test utilities and fixtures.

---

## Critical Architectural Patterns

### Multi-Tenancy with Vaults

**Critical:** All data operations are scoped to a `Vault` (UUID). This provides complete tenant isolation.

- Every `Relationship` has a `vault` field (UUID)
- All storage operations require a `vault` parameter
- JWT tokens include `vault` and `account` claims
- `AuthContext` includes `vault` and `account` fields
- Middleware validates vault access before allowing operations

**Storage Layer Pattern:**

```rust
async fn write(&self, vault: Uuid, relationships: Vec<Relationship>) -> Result<Revision>
async fn read(&self, vault: Uuid, key: &RelationshipKey, revision: Revision) -> Result<Vec<Relationship>>
```

**Authentication Flow:**

1. Extract JWT from request
2. Validate token and extract `vault` + `account` claims
3. Create `AuthContext` with vault/account
4. Validate vault access (basic + database verification)
5. Pass `AuthContext.vault` to all storage operations

See `MULTI_TENANCY.md` for detailed phase tracking.

### Vault Isolation Enforcement

**Never** skip vault validation. All operations must:

1. Extract vault from `AuthContext`
2. Pass vault to storage layer
3. Verify vault exists and account owns it (when using database verification)

**Validation Functions:**

- **Basic validation** (`infera-auth`): `validate_vault_access()` - Checks for nil vault UUID
- **Database verification** (`infera-api`): `vault_validation::validate_vault_access_with_store()` - Verifies vault exists and account owns it

**Files:**
- `crates/infera-auth/src/middleware.rs` - Basic vault validation (no storage dependencies)
- `crates/infera-api/src/vault_validation.rs` - Database-backed vault verification

### Two-Layer Caching

**Cache Layers:**
1. **Authorization Cache**: (subject, resource, permission, revision) → Decision
2. **Expand Cache**: (resource, relation, revision) → subjects

**Properties:**
- Vault-scoped (keys include vault UUID for tenant isolation)
- Revision-aware (keys include revision for consistency)
- LRU eviction via `moka` with configurable capacity and TTL

**Cache Invalidation:**

Performed by `RelationshipService` after mutations:

```rust
let revision = state.relationship_service.write_relationships(vault, relationships.clone()).await?;
let affected_resources: Vec<String> = relationships.iter().map(|r| r.resource.clone()).collect();
state.relationship_service.invalidate_cache_for_resources(&affected_resources).await;
```

**Strategies:**
1. **Selective Invalidation**: `invalidate_cache_for_resources(&[String])` - Only invalidates specific resources
2. **Vault-wide Invalidation**: `invalidate_cache_for_vault(Uuid)` - Invalidates all entries for vault

Handlers **must** call invalidation after mutations:
- `handlers/relationships/write.rs`
- `handlers/relationships/delete.rs`
- `handlers/relationships/delete_bulk.rs`

### Service Layer Pattern

Services separate business logic from protocol adapters (gRPC/REST/AuthZEN).

**Available Services** (`crates/infera-api/src/services/`):

1. **EvaluationService** - Authorization checks
2. **ExpansionService** - Relationship graph expansion
3. **RelationshipService** - Relationship management
4. **ResourceService** - Resource discovery
5. **SubjectService** - Subject discovery
6. **WatchService** - Real-time change streaming

**All service methods:**
- Take `vault: Uuid` as first parameter for multi-tenant isolation
- Work with core types (not protocol-specific formats)
- Are protocol-agnostic (shared by gRPC, REST, AuthZEN)

### Handler Organization

**REST handlers** are in `crates/infera-api/src/handlers/`:
- Organized by resource type (not HTTP method)
- One file per operation
- Naming: `{verb}_{resource}_handler`
- All use `#[tracing::instrument(skip(state))]`
- Shared utilities in `handlers::utils::auth`

**gRPC handlers** are in `crates/infera-api/src/grpc/`:
- Feature-based modules
- Delegation pattern in `grpc/mod.rs`
- Vault scoping via AuthContext in request extensions

---

## Authentication Security

**Only asymmetric algorithms allowed:**
- EdDSA (Ed25519)
- RS256, RS384, RS512

Symmetric algorithms (HS256, etc.) are explicitly rejected.

**JWT Claims Structure:**

```rust
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub vault: String,    // Vault UUID
    pub account: String,  // Account UUID
    pub scopes: Vec<String>,
}
```

**AuthContext Structure:**

```rust
pub struct AuthContext {
    pub tenant_id: String,
    pub client_id: String,
    pub key_id: String,
    pub auth_method: AuthMethod,
    pub scopes: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub jti: Option<String>,
    pub vault: Uuid,
    pub account: Uuid,
}
```

---

## Testing Guidelines

**Test Organization:**
- Unit tests in `#[cfg(test)] mod tests` within source files
- Integration tests in `tests/` directory of each crate
- Fixtures in `crates/infera-test-fixtures`

**Multi-Tenant Tests:**

1. Create test vaults with `Vault::with_id()` or `Vault::new()`
2. Create test accounts with `Account::new()`
3. Set `relationship.vault = vault_id` before operations
4. Use `AuthContext` with correct vault/account fields
5. **Always verify isolation between vaults**

**Authentication Test Helpers** in `crates/infera-auth/tests/common/`:
- `internal_jwt_helpers.rs` - Generate test JWTs
- `mock_jwks.rs` - Mock JWKS server
- `mock_oauth.rs` - Mock OAuth provider

---

## Common Development Patterns

### Adding a New API Endpoint

1. Define request/response types in `infera-types`
2. Add handler in `infera-api/src/handlers/`
3. Extract `AuthContext` via `RequireAuth` extractor
4. Validate vault access using `authorize_request()`
5. Call service from `AppState` with vault parameter
6. Add integration tests in `infera-api/tests/`

### Adding New Storage Operations

1. Add method to `RelationshipStore` trait in `infera-store/src/lib.rs`
2. Implement for `MemoryBackend` in `infera-store/src/memory.rs`
3. Implement for `FoundationDBBackend` if using `fdb` feature
4. **Ensure all operations are vault-scoped**

### Adding Authentication Logic

1. Update JWT claims if needed in `infera-auth/src/jwt.rs`
2. Add validation logic in `infera-auth/src/validation.rs`
3. Update middleware in `infera-auth/src/middleware.rs` (basic validation only - no storage dependencies)
4. For database-backed validation, add to `infera-api/src/vault_validation.rs`

**Important:** Keep `infera-auth` free of storage/cache dependencies (Layer 3). Database operations belong in `infera-api` (Layer 4).

---

## Configuration

Configuration precedence (highest to lowest):

1. Command-line arguments (`--port 8080`)
2. Environment variables (`INFERA__SERVER__PORT=8080`)
3. Configuration file (`config.yaml`)
4. Default values

**Environment variable format:** Use `INFERA__` prefix and `__` separator (e.g., `INFERA__AUTH__ENABLED=true`)

---

## Error Handling Standards

Every error enum **MUST**:

1. **Use `thiserror::Error` derive**
2. **Have a Result type alias**: `pub type Result<T> = std::result::Result<T, MyError>;`
3. **Preserve error chains**: Use `#[from]` or `#[source]` to maintain error context

**Error Conversion Patterns:**

```rust
// Pattern 1: Automatic with #[from]
#[derive(Debug, Error)]
pub enum MyError {
    #[error("Storage error")]
    Store(#[from] infera_types::StoreError),
}

// Pattern 2: Custom with source preservation
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Authentication failed")]
    Auth {
        #[source]
        source: infera_auth::AuthError,
    },
}
```

**Key Rules:**
- At crate boundaries: Convert to public error type
- Within crates: Use Result type alias
- Never stringify errors (loses error chain)
- Test error variants, not messages

---

## Type Organization (infera-types)

The `infera-types` crate is the **single source of truth** for shared types.

**Types belong in infera-types if:**
- Used by multiple crates
- Core domain concepts (Relationship, Vault, Account, Decision)
- Request/response types for APIs
- Shared authentication types (AuthContext, AuthMethod)

**Types stay in implementation crate if:**
- Implementation-specific (e.g., AuthError with JWKS details)
- Only used within a single crate
- Tied to specific runtime/library

**Moving types:** Use re-export pattern for backwards compatibility:

```rust
// NEW: crates/infera-types/src/mytype.rs
pub struct MyType { /* ... */ }

// NEW: crates/infera-some-crate/src/lib.rs
pub use infera_types::MyType;  // Re-export for compatibility
```

---

## Security Notes

- Never use symmetric JWT algorithms (HS256)
- Always validate vault ownership before operations
- Enable replay protection in production
- Follow least-privilege principle for scopes
- Regularly run: `cargo audit`

---

## Troubleshooting

- **Vault errors**: Check `Relationship.vault` is set, `AuthContext` includes vault/account, storage operations receive vault
- **Auth errors**: Verify asymmetric algorithm (EdDSA/RS256), token includes vault/account claims, JWKS URL accessible
- **Build errors**: Run `cargo clean`, check Rust 1.83+, run `cargo update`
