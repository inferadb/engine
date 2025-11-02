# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Follow the directives outlined in AGENTS.md.

---

## Development Commands

### Testing

```bash
# Run all tests (preferred - uses nextest for faster parallel execution)
cargo nextest run --workspace

# Run traditional cargo test (if nextest unavailable)
cargo test --workspace

# Run tests for a specific crate
cargo test -p infera-auth

# Run a single test by name
cargo test test_vault_validation_with_valid_vault

# Run tests with output
cargo test -- --nocapture

# Run tests in watch mode
cargo watch -x 'nextest run --workspace'
```

### Building

```bash
# Build debug binary
cargo build

# Build release binary (optimized)
cargo build --release --workspace

# Build specific crate
cargo build -p infera-core
```

### Code Quality

```bash
# Format code
cargo +nightly fmt --all

# Check formatting (CI mode)
cargo +nightly fmt --check

# Run clippy linter
cargo clippy --workspace --all-targets -- -D warnings

# Auto-fix clippy warnings
cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged

# Run all quality checks (format, lint, test, security audit)
make check
```

### Running the Server

```bash
# Development server with auto-reload
cargo watch -x 'run --bin inferadb'

# Or using make
make dev

# Run release binary
cargo run --release --bin inferadb

# Run with custom config
cargo run --bin inferadb -- --config config.yaml
```

---

## Architecture Overview

InferaDB is a **Relationship-Based Access Control (ReBAC)** authorization engine built as a modular Rust workspace.

### Crate Architecture

The codebase follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                     infera-api                           │
│         REST + gRPC API Layer (Axum + Tonic)             │
├─────────────────────────────────────────────────────────┤
│  infera-auth  │  infera-core  │  infera-cache           │
│  JWT/OAuth    │  Evaluation   │  LRU Caching            │
├─────────────────────────────────────────────────────────┤
│  infera-store │  infera-repl  │  infera-wasm            │
│  Storage      │  Replication  │  WASM Runtime           │
├─────────────────────────────────────────────────────────┤
│            infera-observe + infera-config                │
│         Metrics/Tracing + Configuration                  │
└─────────────────────────────────────────────────────────┘
```

**Core Crates (dependency order from bottom to top):**

1. **infera-types**: Shared type definitions (Relationship, Vault, Account, Decision, etc.). Zero dependencies on other crates.

2. **infera-const**: Compile-time constants and limits.

3. **infera-config**: Configuration management using `config` crate. Supports YAML files, environment variables, and CLI args.

4. **infera-observe**: Observability layer - metrics (Prometheus), tracing (OpenTelemetry), structured logging.

5. **infera-cache**: Two-layer caching system (authorization results + expand trees). Uses `moka` for async LRU cache.

6. **infera-store**: Storage abstraction layer defining `RelationshipStore`, `VaultStore`, and `AccountStore` traits. Implementations:

    - `MemoryBackend` - In-memory HashMap (development/testing)
    - `FoundationDBBackend` - Distributed storage (production)

7. **infera-core**: Policy evaluation engine:

    - IPL (Infera Policy Language) parser
    - Relationship graph traversal
    - Decision evaluation with caching
    - Parallel evaluation for complex queries

8. **infera-wasm**: WebAssembly policy module runtime using `wasmtime`.

9. **infera-repl**: Multi-region replication with conflict resolution.

10. **infera-auth**: Authentication and authorization:

    - JWT validation (EdDSA, RS256 only - no symmetric algorithms)
    - OAuth 2.0 Bearer token support
    - JWKS caching with stale-while-revalidate
    - Vault-based access control middleware
    - Replay protection (in-memory or Redis)

11. **infera-api**: HTTP and gRPC API servers:

    - REST API via Axum
    - gRPC API via Tonic
    - Rate limiting
    - Health checks (liveness, readiness, startup)

12. **infera-bin**: Main binary entry point.

13. **infera-test-fixtures**: Shared test utilities and fixtures.

### Key Architectural Patterns

#### Multi-Tenancy with Vaults

**Critical:** All data operations are scoped to a `Vault` (UUID). This provides complete tenant isolation.

-   Every `Relationship` has a `vault` field (UUID)
-   All storage operations require a `vault` parameter
-   JWT tokens include `vault` and `account` claims
-   `AuthContext` includes `vault` and `account` fields
-   Middleware validates vault access before allowing operations

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

See `MULTI_TENANCY.md` for implementation details and phase tracking.

#### Revision-Based Consistency

All reads and writes use monotonically increasing `Revision` tokens:

-   Each vault has its own revision counter
-   Writes return the new revision
-   Reads specify a revision for snapshot consistency
-   Enables "Read Your Writes" consistency

#### Two-Layer Caching

1. **Authorization Cache**: Caches (subject, resource, permission) → Decision
2. **Expand Cache**: Caches relationship expansion trees

Both caches:

-   Are vault-scoped (keys include vault UUID)
-   Are revision-aware (invalidated on writes)
-   Support selective invalidation by resource

#### Storage Trait Abstraction

The `RelationshipStore` trait enables pluggable backends:

-   Development: `MemoryBackend` (in-memory HashMap)
-   Production: `FoundationDBBackend` (distributed, transactional)

All implementations must support:

-   Vault-scoped operations
-   Revision-based reads
-   Change log for Watch API
-   Atomic write/delete operations

#### API Handler Organization

The REST API handlers follow a **resource-based organization pattern** for maximum maintainability and scalability:

**Directory Structure:**

```
crates/infera-api/src/handlers/
├── mod.rs                 # Module declarations
├── utils/                 # Shared utilities
│   └── auth.rs           # Authentication helpers (get_vault, require_admin_scope, etc.)
├── evaluate/             # Evaluation endpoints
│   ├── mod.rs
│   └── stream.rs         # POST /v1/evaluate (SSE streaming)
├── expand/               # Expand operations
│   ├── mod.rs
│   └── stream.rs         # POST /v1/expand (SSE streaming)
├── relationships/        # Relationship management
│   ├── mod.rs
│   ├── get.rs            # GET /v1/relationships/:id
│   ├── delete.rs         # DELETE /v1/relationships/:id
│   ├── write.rs          # POST /v1/relationships/write (batch)
│   ├── delete_bulk.rs    # POST /v1/relationships/delete (filter-based)
│   └── list.rs           # POST /v1/relationships/list (SSE streaming)
├── resources/            # Resource listing
│   ├── mod.rs
│   └── list.rs           # POST /v1/resources/list (SSE streaming)
├── subjects/             # Subject listing
│   ├── mod.rs
│   └── list.rs           # POST /v1/subjects/list (SSE streaming)
├── simulate/             # Ephemeral evaluation
│   ├── mod.rs
│   └── evaluate.rs       # POST /v1/simulate
├── watch/                # Real-time change streaming
│   ├── mod.rs
│   └── stream.rs         # POST /v1/watch (SSE streaming)
├── accounts/             # Account management (Phase 4)
│   ├── mod.rs
│   ├── create.rs         # POST /v1/accounts
│   ├── list.rs           # GET /v1/accounts
│   ├── get.rs            # GET /v1/accounts/:id
│   ├── update.rs         # PATCH /v1/accounts/:id
│   └── delete.rs         # DELETE /v1/accounts/:id
├── vaults/               # Vault management (Phase 4)
│   ├── mod.rs
│   ├── create.rs         # POST /v1/accounts/:account_id/vaults
│   ├── list.rs           # GET /v1/accounts/:account_id/vaults
│   ├── get.rs            # GET /v1/vaults/:id
│   ├── update.rs         # PATCH /v1/vaults/:id
│   └── delete.rs         # DELETE /v1/vaults/:id
└── authzen/              # AuthZEN compliance endpoints
    ├── mod.rs
    ├── evaluation.rs     # POST /access/v1/evaluation/evaluate
    ├── search.rs         # POST /access/v1/search
    └── well_known.rs     # GET /.well-known/authzen-configuration
```

**Key Patterns:**

1. **One File Per Operation**: Each handler operation is in its own file for clear separation
2. **Resource Grouping**: Handlers organized by resource type (not by HTTP method)
3. **Consistent Naming**: `{verb}_{resource}_handler` (e.g., `create_account_handler`)
4. **Shared Utilities**: Common auth helpers in `handlers::utils::auth`
5. **Comprehensive Documentation**: Each handler has 30+ lines of doc comments with examples
6. **Error Handling**: All handlers return `Result<T, ApiError>` for consistent error responses
7. **Instrumentation**: All handlers use `#[tracing::instrument(skip(state))]`

**Adding New Handlers:**

````rust
// handlers/myresource/myoperation.rs
use crate::{ApiError, AppState, Result, handlers::utils::auth::get_vault};

/// Brief description of what this handler does
///
/// # Authorization
/// - Requires authentication
/// - Requires `inferadb.some-scope` scope
///
/// # Request Body
/// ```json
/// { "field": "value" }
/// ```
///
/// # Response (200 OK)
/// ```json
/// { "result": "success" }
/// ```
///
/// # Errors
/// - 401 Unauthorized: No authentication provided
/// - 403 Forbidden: Missing required scope
/// - 400 Bad Request: Invalid request format
#[tracing::instrument(skip(state))]
pub async fn my_operation_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    // ... extractors
) -> Result<impl IntoResponse> {
    // 1. Extract vault
    let vault = get_vault(&auth.0, state.default_vault);

    // 2. Authorize (scope checks, account ownership, etc.)
    // 3. Validate request
    // 4. Execute operation
    // 5. Return response
}
````

**Router Registration:**

Handlers are imported and registered in `crates/infera-api/src/lib.rs`:

```rust
use handlers::myresource::myoperation::my_operation_handler;

// In create_router():
.route("/v1/myresource", post(my_operation_handler))
```

#### gRPC Service Organization

The gRPC API follows the same **resource-based organization pattern** as the REST handlers for consistency and maintainability:

**Directory Structure:**

```
crates/infera-api/src/grpc/
├── mod.rs                # Service trait implementation + delegation
├── evaluate.rs           # Bidirectional streaming: evaluate
├── expand.rs             # Server streaming: expand
├── relationships.rs      # Client streaming: write/delete relationships
├── list.rs               # Server streaming: list operations
├── watch.rs              # Server streaming: watch changes
├── simulate.rs           # Unary RPC: simulate evaluation
└── health.rs             # Unary RPC: health check
```

**Key Patterns:**

1. **Feature-Based Modules**: Each gRPC method is in its own file grouped by feature
2. **Delegation Pattern**: `grpc/mod.rs` implements the service trait and delegates to submodules
3. **Type Safety**: All streaming types properly defined with Pin<Box<dyn Stream>>
4. **Consistent Signatures**: All methods take `&InferaServiceImpl` and `Request<T>`
5. **Error Handling**: All methods return `Result<Response<T>, Status>`
6. **Vault Scoping**: All operations use vault from AuthContext (via request extensions)

**Module Implementation Pattern:**

The `grpc/mod.rs` contains the service trait implementation skeleton that delegates to submodules:

```rust
pub struct InferaServiceImpl {
    state: AppState,
}

#[tonic::async_trait]
impl InferaService for InferaServiceImpl {
    type EvaluateStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<EvaluateResponse, Status>> + Send + 'static>,
    >;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<EvaluateRequest>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        // Delegate to submodule
        evaluate::evaluate(self, request).await
    }

    // ... other method delegations
}
```

**Adding New gRPC Methods:**

```rust
// grpc/mymethod.rs
use tonic::{Request, Response, Status};
use crate::grpc::InferaServiceImpl;

pub(super) async fn my_method(
    service: &InferaServiceImpl,
    request: Request<MyRequest>,
) -> Result<Response<MyResponse>, Status> {
    // 1. Extract AuthContext from request extensions
    let auth = request.extensions().get::<infera_auth::AuthContext>().cloned();

    // 2. Extract vault
    let vault = auth.as_ref().map(|ctx| ctx.vault).unwrap_or(service.state.default_vault);

    // 3. Validate and execute
    // 4. Return response
    Ok(Response::new(MyResponse { /* ... */ }))
}
```

**Streaming Patterns:**

For server streaming (expand, list, watch):

```rust
type MyStream = std::pin::Pin<
    Box<dyn futures::Stream<Item = Result<MyResponse, Status>> + Send + 'static>
>;

pub(super) async fn my_stream_method(
    service: &InferaServiceImpl,
    request: Request<MyRequest>,
) -> Result<Response<MyStream>, Status> {
    // Create async stream
    let stream = futures::stream::unfold(state, |state| async move {
        // Generate items
        Some((Ok(item), new_state))
    });

    Ok(Response::new(Box::pin(stream)))
}
```

For bidirectional/client streaming (evaluate, relationships):

```rust
pub(super) async fn my_bidirectional_method(
    service: &InferaServiceImpl,
    request: Request<tonic::Streaming<MyRequest>>,
) -> Result<Response<MyStream>, Status> {
    let mut request_stream = request.into_inner();

    // Process stream items
    let stream = async_stream::stream! {
        while let Some(item) = request_stream.message().await? {
            // Process item
            yield Ok(response);
        }
    };

    Ok(Response::new(Box::pin(stream)))
}
```

**Service Registration:**

The gRPC service is registered in `crates/infera-api/src/lib.rs`:

```rust
use crate::grpc::InferaServiceImpl;

// In create_grpc_server():
Server::builder()
    .add_service(InferaServiceServer::new(InferaServiceImpl::new(state)))
    .serve(addr)
    .await
```

---

## Critical Implementation Details

### Vault Isolation Enforcement

**Never** skip vault validation. All operations must:

1. Extract vault from `AuthContext`
2. Pass vault to storage layer
3. Verify vault exists and account owns it (when using `validate_vault_access_with_store`)

**Files:**

-   `crates/infera-auth/src/middleware.rs` - Vault validation functions
-   `crates/infera-auth/tests/vault_auth_tests.rs` - Comprehensive vault tests

### Authentication Security

**Only asymmetric algorithms are allowed:**

-   EdDSA (Ed25519)
-   RS256, RS384, RS512

Symmetric algorithms (HS256, etc.) are explicitly rejected in validation.

**JWT Claims Structure:**

```rust
pub struct Claims {
    pub sub: String,      // subject
    pub iss: String,      // issuer
    pub aud: Vec<String>, // audience
    pub exp: i64,         // expiration
    pub iat: i64,         // issued at
    pub vault: String,    // Vault UUID (Phase 2)
    pub account: String,  // Account UUID (Phase 2)
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
    pub vault: Uuid,      // Phase 2
    pub account: Uuid,    // Phase 2
}
```

### Wildcard Support

Subjects can be wildcards (e.g., `user:*`) to model public resources:

-   Only valid in subject position (not resource or relation)
-   Format must be `type:*` (e.g., `user:*`, `group:*`)
-   Matching checks both exact match AND wildcard type match

**Implementation:**

-   `Relationship::is_wildcard_subject()` - Check if subject is wildcard
-   `Relationship::matches_subject(subject)` - Check if relationship applies to subject
-   `Relationship::validate_wildcard_placement()` - Ensure wildcards only in subject

### IPL (Infera Policy Language)

Policy definitions use IPL syntax:

```ipl
type document {
  relation viewer: user
  relation editor: user | group#member

  permission can_view = viewer | editor
  permission can_edit = editor

  forbid can_view {
    if wasm.call("banned_user_check")
  }
}
```

**Parser:** `crates/infera-core/src/ipl/parser.rs`
**Evaluator:** `crates/infera-core/src/evaluator.rs`

---

## Testing Guidelines

### Test Organization

-   **Unit tests:** In `#[cfg(test)] mod tests` within source files
-   **Integration tests:** In `tests/` directory of each crate
-   **Fixtures:** `crates/infera-test-fixtures` for shared test utilities

### Writing Multi-Tenant Tests

When writing tests involving vaults:

1. Create test vaults with `Vault::with_id()` or `Vault::new()`
2. Create test accounts with `Account::new()`
3. Set `relationship.vault = vault_id` before operations
4. Use `AuthContext` with correct vault/account fields
5. Verify isolation between different vaults

**Example:**

```rust
#[tokio::test]
async fn test_vault_isolation() {
    let vault_a = Uuid::new_v4();
    let vault_b = Uuid::new_v4();
    let account_a = Uuid::new_v4();

    // Write to vault A
    let rel_a = Relationship {
        vault: vault_a,
        resource: "doc:a".to_string(),
        relation: "viewer".to_string(),
        subject: "user:alice".to_string(),
    };
    store.write(vault_a, vec![rel_a]).await?;

    // Verify vault B cannot see vault A's data
    let results = store.read(vault_b, &key, Revision(0)).await?;
    assert!(results.is_empty(), "Vaults must be isolated");
}
```

### Authentication Test Helpers

Use the test helpers in `crates/infera-auth/tests/common/`:

-   `internal_jwt_helpers.rs` - Generate test JWTs
-   `mock_jwks.rs` - Mock JWKS server
-   `mock_oauth.rs` - Mock OAuth provider

---

## Common Development Patterns

### Adding a New API Endpoint

1. Define request/response types in `infera-types`
2. Add handler in `infera-api/src/handlers/`
3. Extract `AuthContext` via `RequireAuth` extractor
4. Validate vault access
5. Call evaluator/store with `auth.vault`
6. Add integration tests in `infera-api/tests/`

### Adding New Storage Operations

1. Add method to `RelationshipStore` trait in `infera-store/src/lib.rs`
2. Implement for `MemoryBackend` in `infera-store/src/memory.rs`
3. Implement for `FoundationDBBackend` if using `fdb` feature
4. Add tests in `infera-store/src/` or `tests/`
5. Ensure all operations are vault-scoped

### Adding Authentication Logic

1. Update JWT claims if needed in `infera-auth/src/jwt.rs`
2. Add validation logic in `infera-auth/src/validation.rs`
3. Update middleware in `infera-auth/src/middleware.rs`
4. Add comprehensive tests in `infera-auth/tests/`

---

## Configuration

Configuration precedence (highest to lowest):

1. Command-line arguments (`--port 8080`)
2. Environment variables (`INFERA__SERVER__PORT=8080`)
3. Configuration file (`config.yaml`)
4. Default values

**Environment variable format:**

-   Use double underscore `__` as separator
-   Prefix with `INFERA__`
-   Example: `INFERA__AUTH__ENABLED=true`

---

## Troubleshooting

### Tests Failing After Vault Changes

If you see "nil UUID" or vault-related errors:

1. Check that all `Relationship` instances have `vault` field set
2. Ensure `AuthContext` includes vault/account
3. Verify storage operations receive vault parameter
4. Check test fixtures set vault field

### Authentication Errors

If JWT validation fails:

1. Verify algorithm is asymmetric (EdDSA, RS256) - no HS256
2. Check token includes `vault` and `account` claims
3. Ensure JWKS URL is accessible
4. Verify issuer matches configuration

### Build Errors

If compilation fails:

1. Run `cargo clean` to clear build cache
2. Check Rust version: `rustc --version` (need 1.83+)
3. Verify all dependencies in Cargo.toml
4. Run `cargo update` to refresh dependencies

---

## Performance Considerations

-   **Caching:** Enable caching for production (default: on)
-   **Worker Threads:** Set `INFERA__SERVER__WORKER_THREADS` to CPU count
-   **Database:** Use FoundationDB for production, not MemoryBackend
-   **Rate Limiting:** Configure per deployment requirements

**Benchmarking:**

```bash
cargo bench --workspace
```

---

## Security Notes

-   Never use symmetric JWT algorithms (HS256) - explicitly rejected
-   Always validate vault ownership before operations
-   Use audit logging for authentication events
-   Enable replay protection in production
-   Follow least-privilege principle for scopes
-   Regularly run security audits: `cargo audit`

---

## Multi-Tenancy Implementation Status

See `MULTI_TENANCY.md` for detailed phase tracking.

**Completed:**

-   ✅ Phase 1: Data Model & Storage (Vault/Account types, storage layer)
-   ✅ Phase 2: Authentication Integration (JWT claims, vault validation)
-   ✅ Phase 3: API Handler Updates (vault-scoped endpoints)
-   ✅ Phase 4: Account & Vault Management APIs (10 REST endpoints with admin/owner authorization)

**Pending:**

-   Phase 5: Initialization & Migration
-   Phase 6: Cache Isolation
-   Phase 7: Testing & Documentation
