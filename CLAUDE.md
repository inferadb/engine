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

10. **infera-auth**: Authentication and authorization (Layer 3):
    - JWT validation (EdDSA, RS256 only - no symmetric algorithms)
    - OAuth 2.0 Bearer token support
    - JWKS caching with stale-while-revalidate
    - Basic vault validation (nil checks, AuthContext extraction)
    - Replay protection (in-memory or Redis)
    - **Note:** Does NOT depend on storage or cache layers (Layer 2) - maintains clean layering

11. **infera-api**: HTTP and gRPC API servers:
    - REST API via Axum
    - gRPC API via Tonic
    - Service layer (EvaluationService, ExpansionService, RelationshipService, etc.)
    - Rate limiting
    - Health checks (liveness, readiness, startup)

12. **infera-bin**: Main binary entry point.

13. **infera-test-fixtures**: Shared test utilities and fixtures.

### Key Architectural Patterns

#### Multi-Tenancy with Vaults

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

See `MULTI_TENANCY.md` for implementation details and phase tracking.

#### Revision-Based Consistency

All reads and writes use monotonically increasing `Revision` tokens:

- Each vault has its own revision counter
- Writes return the new revision
- Reads specify a revision for snapshot consistency
- Enables "Read Your Writes" consistency

#### Two-Layer Caching

InferaDB uses a sophisticated two-layer caching system to optimize authorization decisions and relationship expansions.

**Cache Layers:**

1. **Authorization Cache**: Caches (subject, resource, permission, revision) → Decision
2. **Expand Cache**: Caches relationship expansion trees (resource, relation, revision) → subjects

**Architecture:**

- Single `Arc<AuthCache>` instance stored in `AppState`
- Shared across all services (EvaluationService, ResourceService, SubjectService, etc.)
- Services pass cache as `Option<Arc<AuthCache>>` parameter to evaluators
- Respects `config.cache.enabled` flag for easy disable in development/testing

**Cache Properties:**

- **Vault-scoped**: Keys include vault UUID for complete tenant isolation
- **Revision-aware**: Keys include revision to ensure consistency
- **LRU eviction**: Uses `moka` async cache with configurable capacity
- **TTL support**: Configurable time-to-live (default: 300 seconds)
- **Statistics tracking**: Hit/miss rates, entry counts, invalidation counts

**Cache Invalidation:**

Cache invalidation is performed by `RelationshipService` after mutations:

```rust
// In handlers/relationships/write.rs
let revision = state.relationship_service.write_relationships(vault, relationships.clone()).await?;

// Invalidate cache for affected resources
let affected_resources: Vec<String> = relationships.iter().map(|r| r.resource.clone()).collect();
state.relationship_service.invalidate_cache_for_resources(&affected_resources).await;
```

**Invalidation Strategies:**

1. **Selective Invalidation** (preferred): `invalidate_cache_for_resources(&[String])`
    - Only invalidates entries for specific resources
    - Efficient for targeted updates
    - Uses secondary indexes for fast lookup

2. **Vault-wide Invalidation**: `invalidate_cache_for_vault(Uuid)`
    - Invalidates all entries for a specific vault
    - Used when revision changes affect entire vault
    - Maintains isolation between vaults

**Implementation Details:**

- **Service Integration**: All services that create evaluators pass the shared cache:

    ```rust
    let evaluator = Evaluator::new_with_cache(store, schema, wasm_host, cache, vault);
    ```

- **Handler Responsibilities**: Handlers must call invalidation after successful mutations:
    - `handlers/relationships/write.rs` - Invalidates after batch writes
    - `handlers/relationships/delete.rs` - Invalidates after single delete
    - `handlers/relationships/delete_bulk.rs` - Invalidates after bulk delete

- **Test Coverage**: Comprehensive integration tests in `tests/integration/cache_invalidation_tests.rs`:
    - Cache population and hit/miss tracking
    - Invalidation on write and delete
    - Selective vs vault-wide invalidation
    - Vault isolation in cache operations
    - Multiple writes to same resource
    - Bulk operations

**Performance Considerations:**

- Cache keys include revision, so writes naturally invalidate stale entries
- Selective invalidation reduces re-evaluation overhead
- Secondary indexes enable O(1) resource-based invalidation
- Async cache operations don't block request threads

#### Storage Trait Abstraction

The `RelationshipStore` trait enables pluggable backends:

- Development: `MemoryBackend` (in-memory HashMap)
- Production: `FoundationDBBackend` (distributed, transactional)

All implementations must support:

- Vault-scoped operations
- Revision-based reads
- Change log for Watch API
- Atomic write/delete operations

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

## Service Layer Architecture

InferaDB uses a **service layer pattern** to separate business logic from protocol adapters. This provides:

- **Protocol Independence**: Business logic works with core types, not gRPC/REST/AuthZEN formats
- **Vault Scoping**: Each service call receives a vault UUID for multi-tenant isolation
- **Testability**: Services can be unit tested independently of protocols
- **Code Reuse**: Same service methods used by gRPC, REST, and AuthZEN handlers

### Available Services

Located in `crates/infera-api/src/services/`:

1. **EvaluationService** (`evaluation.rs`) - Authorization checks
    - `evaluate(vault, request)` - Check if subject has permission on resource
    - `evaluate_with_trace(vault, request)` - Evaluation with debug trace

2. **ExpansionService** (`expansion.rs`) - Relationship graph expansion
    - `expand(vault, request)` - Discover all subjects with permission on resource

3. **RelationshipService** (`relationships.rs`) - Relationship management
    - `write_relationships(vault, relationships)` - Create relationships
    - `delete_relationships(vault, filter, limit)` - Delete by filter
    - `list_relationships(vault, request)` - List with pagination

4. **ResourceService** (`resources.rs`) - Resource discovery
    - `list_resources(vault, request)` - List resources subject can access

5. **SubjectService** (`subjects.rs`) - Subject discovery
    - `list_subjects(vault, request)` - List subjects with access to resource

6. **WatchService** (`watch.rs`) - Real-time change streaming
    - `watch_changes(vault, cursor, resource_type)` - Stream relationship changes

### Service Creation Pattern

Services are created once during application startup in `AppState::new()`:

```rust
pub struct AppState {
    pub store: Arc<dyn infera_store::InferaStore>,
    pub config: Arc<Config>,
    pub jwks_cache: Option<Arc<JwksCache>>,
    pub default_vault: Uuid,
    pub default_account: Uuid,

    // Services
    pub evaluation_service: Arc<EvaluationService>,
    pub expansion_service: Arc<ExpansionService>,
    pub relationship_service: Arc<RelationshipService>,
    pub resource_service: Arc<ResourceService>,
    pub subject_service: Arc<SubjectService>,
    pub watch_service: Arc<WatchService>,
}

impl AppState {
    pub fn new(
        store: Arc<dyn infera_store::InferaStore>,
        schema: Arc<infera_core::ipl::Schema>,
        wasm_host: Option<Arc<infera_wasm::WasmHost>>,
        config: Arc<Config>,
        jwks_cache: Option<Arc<JwksCache>>,
        default_vault: Uuid,
        default_account: Uuid,
    ) -> Self {
        let store_rs = Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>;

        Self {
            evaluation_service: Arc::new(EvaluationService::new(
                Arc::clone(&store_rs),
                Arc::clone(&schema),
                wasm_host.clone(),
            )),
            expansion_service: Arc::new(ExpansionService::new(
                Arc::clone(&store_rs),
                Arc::clone(&schema),
                wasm_host.clone(),
            )),
            relationship_service: Arc::new(RelationshipService::new(
                Arc::clone(&store_rs),
                Arc::clone(&schema),
                wasm_host.clone(),
            )),
            resource_service: Arc::new(ResourceService::new(
                Arc::clone(&store_rs),
                Arc::clone(&schema),
                wasm_host.clone(),
            )),
            subject_service: Arc::new(SubjectService::new(
                Arc::clone(&store_rs),
                Arc::clone(&schema),
                wasm_host,
            )),
            watch_service: Arc::new(WatchService::new(store_rs)),
            store,
            config,
            jwks_cache,
            default_vault,
            default_account,
        }
    }
}
```

### Handler Pattern

All protocol handlers (gRPC, REST, AuthZEN) follow the same pattern:

```rust
// 1. Extract vault from auth context
let vault = authorize_request(
    &auth.0,
    state.default_vault,
    state.config.auth.enabled,
    &[SCOPE_CHECK],
)?;

// 2. Convert protocol request to core types
let core_request = EvaluateRequest {
    subject: protocol_request.subject,
    resource: protocol_request.resource,
    permission: protocol_request.permission,
};

// 3. Call service with vault parameter
let decision = state.evaluation_service
    .evaluate(vault, core_request)
    .await?;

// 4. Convert service response back to protocol format
Ok(ProtocolResponse {
    decision: decision.to_string(),
})
```

### Adding a New Service

1. Create service file in `crates/infera-api/src/services/`
2. Define service struct with dependencies (store, schema, wasm_host)
3. Implement methods that take `vault: Uuid` as first parameter
4. Add comprehensive doc comments with examples
5. Add service to `AppState` struct
6. Create service instance in `AppState::new()`
7. Export from `services/mod.rs`
8. Add unit tests in same file

### Service Testing Pattern

Services should have unit tests that verify:

- Vault isolation (operations on vault A don't affect vault B)
- Input validation
- Business logic correctness
- Error handling

```rust
#[tokio::test]
async fn test_vault_isolation() {
    let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());
    let schema = Arc::new(Schema::new(vec![]));
    let service = EvaluationService::new(store, schema, None);

    let vault_a = Uuid::new_v4();
    let vault_b = Uuid::new_v4();

    // Write to vault A
    // Verify vault B cannot see vault A's data
}
```

---

## Critical Implementation Details

### Vault Isolation Enforcement

**Never** skip vault validation. All operations must:

1. Extract vault from `AuthContext`
2. Pass vault to storage layer
3. Verify vault exists and account owns it (when using database verification)

**Validation Functions:**

- **Basic validation** (`infera-auth`): `validate_vault_access()` - Checks for nil vault UUID and validates AuthContext
- **Database verification** (`infera-api`): `vault_validation::validate_vault_access_with_store()` - Includes storage lookup to verify vault exists and account owns it

**Files:**

- `crates/infera-auth/src/middleware.rs` - Basic vault validation (no storage dependencies)
- `crates/infera-api/src/vault_validation.rs` - Database-backed vault verification (requires VaultStore)

### Authentication Security

**Only asymmetric algorithms are allowed:**

- EdDSA (Ed25519)
- RS256, RS384, RS512

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

- Only valid in subject position (not resource or relation)
- Format must be `type:*` (e.g., `user:*`, `group:*`)
- Matching checks both exact match AND wildcard type match

**Implementation:**

- `Relationship::is_wildcard_subject()` - Check if subject is wildcard
- `Relationship::matches_subject(subject)` - Check if relationship applies to subject
- `Relationship::validate_wildcard_placement()` - Ensure wildcards only in subject

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

- **Unit tests:** In `#[cfg(test)] mod tests` within source files
- **Integration tests:** In `tests/` directory of each crate
- **Fixtures:** `crates/infera-test-fixtures` for shared test utilities

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
5. Call appropriate service from `AppState` with vault parameter (e.g., `state.evaluation_service.evaluate(vault, ...)`)
6. Services handle all business logic and are protocol-agnostic
7. Add integration tests in `infera-api/tests/`

### Adding New Storage Operations

1. Add method to `RelationshipStore` trait in `infera-store/src/lib.rs`
2. Implement for `MemoryBackend` in `infera-store/src/memory.rs`
3. Implement for `FoundationDBBackend` if using `fdb` feature
4. Add tests in `infera-store/src/` or `tests/`
5. Ensure all operations are vault-scoped

### Adding Authentication Logic

1. Update JWT claims if needed in `infera-auth/src/jwt.rs`
2. Add validation logic in `infera-auth/src/validation.rs`
3. Update middleware in `infera-auth/src/middleware.rs` (basic validation only - no storage dependencies)
4. For database-backed validation, add to `infera-api/src/vault_validation.rs`
5. Add comprehensive tests in `infera-auth/tests/` or `infera-api/tests/`

**Important:** Keep `infera-auth` free of storage/cache dependencies (Layer 3). Database-backed operations belong in `infera-api` (Layer 4).

---

## Configuration

Configuration precedence (highest to lowest):

1. Command-line arguments (`--port 8080`)
2. Environment variables (`INFERA__SERVER__PORT=8080`)
3. Configuration file (`config.yaml`)
4. Default values

**Environment variable format:**

- Use double underscore `__` as separator
- Prefix with `INFERA__`
- Example: `INFERA__AUTH__ENABLED=true`

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

- **Caching:** Enable caching for production (default: on)
- **Worker Threads:** Set `INFERA__SERVER__WORKER_THREADS` to CPU count
- **Database:** Use FoundationDB for production, not MemoryBackend
- **Rate Limiting:** Configure per deployment requirements

**Benchmarking:**

```bash
# Run all benchmarks
cargo bench --workspace

# Run specific benchmark suite
cargo bench --package infera-core --bench evaluator
cargo bench --package infera-api --bench api_throughput

# Compare against baseline
cargo bench --bench evaluator -- --baseline my-baseline

# See BENCHMARKS.md for detailed usage
```

**Memory Leak Detection:**

```bash
# Run short memory leak tests (CI-friendly, <5 min)
cargo test --test memory_leak_tests

# Run 24-hour stress tests (manual execution)
cargo test --test memory_leak_tests test_24h_authorization_stress -- --ignored --nocapture
cargo test --test memory_leak_tests test_24h_mixed_workload -- --ignored --nocapture

# Run with valgrind (Linux)
valgrind --leak-check=full cargo test --test memory_leak_tests

# See MEMORY_PROFILING.md for detailed profiling tools and usage
```

---

## Security Notes

- Never use symmetric JWT algorithms (HS256) - explicitly rejected
- Always validate vault ownership before operations
- Use audit logging for authentication events
- Enable replay protection in production
- Follow least-privilege principle for scopes
- Regularly run security audits: `cargo audit`

---

## Error Handling Standards

All error handling in InferaDB follows standardized patterns for consistency, maintainability, and proper error chain preservation.

### Error Type Requirements

Every error enum **MUST**:

1. **Use `thiserror::Error` derive:**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MyError {
    #[error("Clear description: {0}")]
    Variant(String),
}
```

2. **Have a Result type alias:**

```rust
pub type Result<T> = std::result::Result<T, MyError>;
```

3. **Preserve error chains when wrapping:**

```rust
// ✅ GOOD: Preserves source error
#[error("Operation failed")]
Wrapped(#[from] SomeOtherError),

// ❌ BAD: Loses source error
#[error("Operation failed: {0}")]
Wrapped(String),
```

### Error Conversion Patterns

#### Pattern 1: Automatic Conversion with `#[from]`

Use this when you want automatic `From` implementation and error chain preservation:

```rust
#[derive(Debug, Error)]
pub enum MyError {
    #[error("Storage error")]
    Store(#[from] infera_types::StoreError),  // Auto-implements From<StoreError>
}
```

#### Pattern 2: Custom Conversion with Source Preservation

Use this when you need custom conversion logic but still want to preserve the error chain:

```rust
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Authentication failed")]
    Auth {
        #[source]  // Preserves error chain for std::error::Error::source()
        source: infera_auth::AuthError,
    },
}

impl From<infera_auth::AuthError> for ApiError {
    fn from(source: infera_auth::AuthError) -> Self {
        Self::Auth { source }
    }
}
```

#### Pattern 3: Internal Errors with anyhow (NOT for public APIs)

Use `anyhow` for internal error propagation where you need rich context but don't need structured error types:

```rust
use anyhow::{Context, Result};

async fn internal_operation() -> Result<Data> {
    store.get_data()
        .await
        .context("Failed to retrieve data from store")?
}
```

**⚠️ Important:** Convert `anyhow::Error` to public error types at crate boundaries.

### Error Handling Guidelines

1. **At crate boundaries:** Convert to the crate's public error type
2. **Within crates:** Use Result type alias for cleaner signatures
3. **For context:** Use `.context()` with anyhow internally, structured variants externally
4. **For aggregation:** Wrap multiple errors in enum variants, don't stringify
5. **For testing:** Match on error variants, not error message strings

### Anti-Patterns to Avoid

❌ **Stringifying errors and losing the error chain:**

```rust
.map_err(|e| MyError::Internal(e.to_string()))  // Loses error chain!
```

✅ **Instead, preserve the error:**

```rust
.map_err(|e| MyError::Internal { source: e })?
// or use #[from] for automatic conversion
```

❌ **Generic String variants:**

```rust
#[error("Internal error: {0}")]
Internal(String),  // Too generic, no structure, no source
```

✅ **Use structured variants:**

```rust
#[error("Internal operation failed: {operation}")]
InternalOperation {
    operation: String,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}
```

❌ **No Result type alias (verbose signatures):**

```rust
fn operation() -> std::result::Result<T, MyVeryLongErrorTypeName>
```

✅ **Use Result alias:**

```rust
pub type Result<T> = std::result::Result<T, MyError>;

fn operation() -> Result<T>  // Clean and concise
```

### Example: Complete Error Module

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Entity not found: {entity_type}:{entity_id}")]
    NotFound {
        entity_type: String,
        entity_id: String,
    },

    #[error("Database error during {operation}")]
    Database {
        operation: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Serialization failed")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;
```

### Testing Error Handling

**Test error variants, not error messages:**

```rust
// ❌ BAD: Fragile, breaks if message changes
assert_eq!(err.to_string(), "Entity not found");

// ✅ GOOD: Robust, tests actual error type
assert!(matches!(err, StorageError::NotFound { .. }));
```

---

## Multi-Tenancy Implementation Status

See `MULTI_TENANCY.md` for detailed phase tracking.

**Completed:**

- ✅ Phase 1: Data Model & Storage (Vault/Account types, storage layer)
- ✅ Phase 2: Authentication Integration (JWT claims, vault validation)
- ✅ Phase 3: API Handler Updates (vault-scoped endpoints)
- ✅ Phase 4: Account & Vault Management APIs (10 REST endpoints with admin/owner authorization)

**Pending:**

- Phase 5: Initialization & Migration
- Phase 6: Cache Isolation
- Phase 7: Testing & Documentation

---

## Type Organization and Centralization

### infera-types: The Foundation Crate

The `infera-types` crate serves as the **single source of truth** for all shared type definitions. It has **zero dependencies** on other internal crates to prevent circular dependencies.

**Key Principles:**

1. **Types belong in infera-types if they are:**
    - Used by multiple crates
    - Core domain concepts (Relationship, Vault, Account, Decision)
    - Request/response types for APIs
    - Shared authentication types (AuthContext, AuthMethod)
    - Common error types used across boundaries

2. **Types should stay in their implementation crate if they are:**
    - Implementation-specific (e.g., AuthError with JWKS/OAuth details)
    - Only used within a single crate
    - Tied to a specific runtime or library (e.g., WASM types)
    - Configuration types (belong in infera-config)

### Current infera-types Organization

```
src/
  lib.rs          - Main exports
  account.rs      - Account multi-tenancy type
  vault.rs        - Vault and SystemConfig
  auth.rs         - AuthContext and AuthMethod
```

### Adding New Types to infera-types

**Step-by-step process:**

1. Create a new module file (e.g., `src/mytype.rs`)
2. Define the type with appropriate derives (typically `Debug, Clone, Serialize, Deserialize`)
3. Add comprehensive doc comments
4. Include tests in the same file
5. Export from `lib.rs`:
    ```rust
    pub mod mytype;
    pub use mytype::MyType;
    ```

### Moving Types from Other Crates

**Use the re-export pattern for backwards compatibility:**

```rust
// OLD: crates/infera-some-crate/src/lib.rs
pub struct MyType { /* ... */ }

// NEW: crates/infera-types/src/mytype.rs
pub struct MyType { /* ... */ }

// NEW: crates/infera-some-crate/src/lib.rs
pub use infera_types::MyType;  // Re-export for backwards compatibility
```

**Benefits:**

- Zero breaking changes for consumers
- Clean migration path
- Maintains import compatibility

### Circular Dependency Prevention

**Dependency Architecture (5 layers):**

```
Layer 0 (Foundation):  infera-types, infera-const
Layer 1 (Utilities):   infera-config, infera-observe
Layer 2 (Storage):     infera-store, infera-cache
Layer 3 (Runtime):     infera-wasm, infera-core, infera-auth
Layer 4 (Application): infera-repl, infera-api
Layer 5 (Binary):      infera-bin
```

**Rules:**

- Types flow **downward only** (foundation → utilities → storage → runtime → application)
- Dependencies flow **downward only** (higher layers can depend on lower layers, never the reverse)
- infera-types **never** depends on other internal crates
- If a type is needed by multiple layers, it belongs in the **lowest common layer**
- When in doubt, put it in **infera-types**

**Layer Discipline:**

Layer violations (higher layers depending on lower layers, or circular dependencies) must be fixed immediately by:

1. Moving code to the appropriate layer
2. Refactoring to remove the dependency
3. Extracting shared types to a lower layer (typically infera-types)

**Example:** Task 2.4 fixed layer violations where `infera-auth` (Layer 3) depended on `infera-store` (Layer 2). The solution was to move the database-dependent validation function (`validate_vault_access_with_store`) to `infera-api` (Layer 4), where it naturally belongs with other API-layer operations.

### Common Patterns

**1. Serialization Attributes:**

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]  // For API compatibility
pub enum Decision {
    Allow,
    Deny,
}
```

**2. Request/Response Pairs:**

```rust
pub struct CreateResourceRequest { /* ... */ }
pub struct CreateResourceResponse { /* ... */ }
```

**3. Helper Constructors:**

```rust
impl DeleteFilter {
    pub fn exact(resource: String, relation: String, subject: String) -> Self { /* ... */ }
    pub fn by_resource(resource: String) -> Self { /* ... */ }
}
```

### Migration Checklist

When moving a type to infera-types:

- [ ] Create module file in `crates/infera-types/src/`
- [ ] Move type definition with all derives and attributes
- [ ] Move all impl blocks and methods
- [ ] Move all tests
- [ ] Add module declaration to `lib.rs`
- [ ] Add public re-export to `lib.rs`
- [ ] Replace original with re-export
- [ ] Add infera-types dependency if needed
- [ ] Run `cargo test -p infera-types`
- [ ] Run `cargo test` on affected crates
- [ ] Run `cargo test --workspace`
- [ ] Run `cargo +nightly fmt --all`
- [ ] Run `cargo clippy --workspace -- -D warnings`

### Examples

**Good - Type belongs in infera-types:**

```rust
// Used by infera-api, infera-auth, tests
pub struct AuthContext {
    pub vault: Uuid,
    pub account: Uuid,
    // ...
}
```

**Good - Type stays in implementation crate:**

```rust
// Only used within infera-auth, has impl-specific details
pub enum AuthError {
    JWKSFetchFailed(String),      // HTTP implementation detail
    TokenDecodeFailed(String),     // JWT library detail
    ReplayProtectionError(String), // Optional feature detail
}
```

### Future Improvements

Tracked in `PLAN.md`:

- Phase 3: Move cache key types to infera-types
- Phase 4: Reorganize lib.rs into feature-based modules
- Add cargo-deny to enforce dependency rules
