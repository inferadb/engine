# InferaDB Architecture Patterns

This document covers critical architectural patterns used throughout InferaDB.

## Table of Contents

- [Multi-Tenancy with Vaults](#multi-tenancy-with-vaults)
- [Vault Isolation Enforcement](#vault-isolation-enforcement)
- [Two-Layer Caching](#two-layer-caching)
- [Service Layer Pattern](#service-layer-pattern)
- [Handler Organization](#handler-organization)

---

## Multi-Tenancy with Vaults

**Critical:** All data operations are scoped to a `Vault` (UUID). This provides complete tenant isolation.

### Key Principles

- Every `Relationship` has a `vault` field (UUID)
- All storage operations require a `vault` parameter
- JWT tokens include `vault` and `account` claims
- `AuthContext` includes `vault` and `account` fields
- Middleware validates vault access before allowing operations

### Storage Layer Pattern

```rust
async fn write(&self, vault: Uuid, relationships: Vec<Relationship>) -> Result<Revision>
async fn read(&self, vault: Uuid, key: &RelationshipKey, revision: Revision) -> Result<Vec<Relationship>>
```

All storage operations **MUST** include the vault parameter as the first argument.

### Authentication Flow

1. Extract JWT from request
2. Validate token and extract `vault` + `account` claims
3. Create `AuthContext` with vault/account
4. Validate vault access (basic + database verification)
5. Pass `AuthContext.vault` to all storage operations

See `MULTI_TENANCY.md` for detailed phase tracking and implementation status.

---

## Vault Isolation Enforcement

**Never** skip vault validation. All operations must:

1. Extract vault from `AuthContext`
2. Pass vault to storage layer
3. Verify vault exists and account owns it (when using database verification)

### Validation Functions

**Basic validation** (`infera-auth` crate):

- Function: `validate_vault_access()`
- Checks for nil vault UUID
- Validates AuthContext structure
- No storage dependencies (Layer 3)

**Database verification** (`infera-api` crate):

- Function: `vault_validation::validate_vault_access_with_store()`
- Verifies vault exists in storage
- Verifies account owns the vault
- Requires VaultStore dependency (Layer 4)

### Implementation Files

- `crates/infera-auth/src/middleware.rs` - Basic vault validation (no storage dependencies)
- `crates/infera-api/src/vault_validation.rs` - Database-backed vault verification (requires VaultStore)

### Example: Vault-Scoped Handler

```rust
#[tracing::instrument(skip(state))]
pub async fn some_handler(
    auth: infera_auth::extractor::OptionalAuth,
    State(state): State<AppState>,
    Json(request): Json<SomeRequest>,
) -> Result<impl IntoResponse> {
    // 1. Extract vault from auth context
    let vault = get_vault(&auth.0, state.default_vault);

    // 2. Authorize (scope checks, etc.)
    require_scope(&auth.0, SCOPE_RELATIONSHIPS_WRITE)?;

    // 3. Call service with vault parameter
    let result = state.some_service
        .do_operation(vault, request)
        .await?;

    Ok(Json(result))
}
```

---

## Two-Layer Caching

InferaDB uses a sophisticated two-layer caching system to optimize authorization decisions and relationship expansions.

### Cache Layers

1. **Authorization Cache**: Caches `(subject, resource, permission, revision) → Decision`
2. **Expand Cache**: Caches relationship expansion trees `(resource, relation, revision) → subjects`

### Architecture

- Single `Arc<AuthCache>` instance stored in `AppState`
- Shared across all services (EvaluationService, ResourceService, SubjectService, etc.)
- Services pass cache as `Option<Arc<AuthCache>>` parameter to evaluators
- Respects `config.cache.enabled` flag for easy disable in development/testing

### Cache Properties

- **Vault-scoped**: Keys include vault UUID for complete tenant isolation
- **Revision-aware**: Keys include revision to ensure consistency
- **LRU eviction**: Uses `moka` async cache with configurable capacity
- **TTL support**: Configurable time-to-live (default: 300 seconds)
- **Statistics tracking**: Hit/miss rates, entry counts, invalidation counts

### Cache Invalidation

Cache invalidation is performed by `RelationshipService` after mutations:

```rust
// In handlers/relationships/write.rs
let revision = state.relationship_service
    .write_relationships(vault, relationships.clone())
    .await?;

// Invalidate cache for affected resources
let affected_resources: Vec<String> = relationships
    .iter()
    .map(|r| r.resource.clone())
    .collect();

state.relationship_service
    .invalidate_cache_for_resources(&affected_resources)
    .await;
```

### Invalidation Strategies

1. **Selective Invalidation** (preferred): `invalidate_cache_for_resources(&[String])`
   - Only invalidates entries for specific resources
   - Efficient for targeted updates
   - Uses secondary indexes for fast lookup

2. **Vault-wide Invalidation**: `invalidate_cache_for_vault(Uuid)`
   - Invalidates all entries for a specific vault
   - Used when revision changes affect entire vault
   - Maintains isolation between vaults

### Handler Responsibilities

Handlers **must** call invalidation after successful mutations:

- `handlers/relationships/write.rs` - Invalidates after batch writes
- `handlers/relationships/delete.rs` - Invalidates after single delete
- `handlers/relationships/delete_bulk.rs` - Invalidates after bulk delete

### Performance Considerations

- Cache keys include revision, so writes naturally invalidate stale entries
- Selective invalidation reduces re-evaluation overhead
- Secondary indexes enable O(1) resource-based invalidation
- Async cache operations don't block request threads

---

## Service Layer Pattern

Services separate business logic from protocol adapters (gRPC/REST/AuthZEN).

### Benefits

- **Protocol Independence**: Business logic works with core types, not protocol-specific formats
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
    pub default_vault: Uuid,
    pub default_organization: Uuid,

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
        default_vault: Uuid,
        default_organization: Uuid,
    ) -> Self {
        let store_rs = Arc::clone(&store) as Arc<dyn infera_store::RelationshipStore>;

        Self {
            evaluation_service: Arc::new(EvaluationService::new(
                Arc::clone(&store_rs),
                Arc::clone(&schema),
                wasm_host.clone(),
            )),
            // ... other services
            store,
            config,
            default_vault,
            default_organization,
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

---

## Handler Organization

### REST Handlers

REST API handlers are organized in `crates/infera-api/src/handlers/`:

**Organization Principles:**

- Organized by resource type (not HTTP method)
- One file per operation
- Naming convention: `{verb}_{resource}_handler`
- All use `#[tracing::instrument(skip(state))]`
- Shared utilities in `handlers::utils::auth`

**Directory Structure:**

```text
crates/infera-api/src/handlers/
├── mod.rs                 # Module declarations
├── utils/                 # Shared utilities
│   └── auth.rs           # Authentication helpers
├── evaluate/             # Evaluation endpoints
│   └── stream.rs         # POST /v1/evaluate
├── expand/               # Expand operations
│   └── stream.rs         # POST /v1/expand
├── relationships/        # Relationship management
│   ├── get.rs            # GET /v1/relationships/:id
│   ├── delete.rs         # DELETE /v1/relationships/:id
│   ├── write.rs          # POST /v1/relationships/write
│   ├── delete_bulk.rs    # POST /v1/relationships/delete
│   └── list.rs           # POST /v1/relationships/list
├── resources/            # Resource listing
│   └── list.rs           # POST /v1/resources/list
├── subjects/             # Subject listing
│   └── list.rs           # POST /v1/subjects/list
├── simulate/             # Ephemeral evaluation
│   └── evaluate.rs       # POST /v1/simulate
├── watch/                # Real-time change streaming
│   └── stream.rs         # POST /v1/watch
├── accounts/             # Account management
│   ├── create.rs         # POST /v1/accounts
│   ├── list.rs           # GET /v1/accounts
│   ├── get.rs            # GET /v1/accounts/:id
│   ├── update.rs         # PATCH /v1/accounts/:id
│   └── delete.rs         # DELETE /v1/accounts/:id
└── vaults/               # Vault management
    ├── create.rs         # POST /v1/accounts/:account_id/vaults
    ├── list.rs           # GET /v1/accounts/:account_id/vaults
    ├── get.rs            # GET /v1/vaults/:id
    ├── update.rs         # PATCH /v1/vaults/:id
    └── delete.rs         # DELETE /v1/vaults/:id
```

### gRPC Handlers

gRPC handlers are organized in `crates/infera-api/src/grpc/`:

**Organization Principles:**

- Feature-based modules
- Delegation pattern in `grpc/mod.rs`
- Type safety with Pin<Box<dyn Stream>>
- Vault scoping via AuthContext in request extensions

**Directory Structure:**

```text
crates/infera-api/src/grpc/
├── mod.rs                # Service trait implementation + delegation
├── evaluate.rs           # Bidirectional streaming: evaluate
├── expand.rs             # Server streaming: expand
├── relationships.rs      # Client streaming: write/delete
├── list.rs               # Server streaming: list operations
├── watch.rs              # Server streaming: watch changes
├── simulate.rs           # Unary RPC: simulate evaluation
└── health.rs             # Unary RPC: health check
```

**Delegation Pattern:**

```rust
// grpc/mod.rs
pub struct InferaServiceImpl {
    state: AppState,
}

#[tonic::async_trait]
impl InferaService for InferaServiceImpl {
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

---

## Related Documentation

- [Multi-Tenancy Implementation](../MULTI_TENANCY.md)
- [Service Layer Tests](../crates/infera-api/tests/)
- [Handler Examples](../crates/infera-api/src/handlers/)
- [gRPC Service Definition](../proto/infera/v1/service.proto)

---

Last updated: 2025-11-03
