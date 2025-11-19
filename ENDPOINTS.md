# InferaDB API Endpoints Reference

Comprehensive mapping of InferaDB API endpoints compared to competitors (SpiceDB, OpenFGA, Oso, WorkOS FGA, Cedar/AVP).

**Last Updated**: 2025-10-31
**Version**: 0.1.0

---

## Table of Contents

- [InferaDB Endpoints](#inferadb-endpoints)
    - [gRPC API](#grpc-api)
    - [REST/HTTP API](#resthttp-api)
- [Endpoint Comparison Matrix](#endpoint-comparison-matrix)
- [Detailed Endpoint Comparisons](#detailed-endpoint-comparisons)
- [Missing Endpoints](#missing-endpoints)

---

## InferaDB Endpoints

### gRPC API

Defined in: `crates/infera-api/proto/infera.proto`

| RPC Method            | Request                    | Response                           | Purpose                                                               |
| --------------------- | -------------------------- | ---------------------------------- | --------------------------------------------------------------------- |
| `Evaluate`            | `stream EvaluateRequest`   | `stream EvaluateResponse`          | Evaluate permissions (streaming for single/batch, optional trace)     |
| `Simulate`            | `SimulateRequest`          | `SimulateResponse`                 | Test authorization with ephemeral relationships (what-if testing)     |
| `Expand`              | `ExpandRequest`            | `stream ExpandResponse`            | Expand relation into userset tree (streaming for progressive results) |
| `ListResources`       | `ListResourcesRequest`     | `stream ListResourcesResponse`     | Lookup all resources accessible by a subject                          |
| `ListSubjects`        | `ListSubjectsRequest`      | `stream ListSubjectsResponse`      | Lookup all subjects that have access to a resource                    |
| `ListRelationships`   | `ListRelationshipsRequest` | `stream ListRelationshipsResponse` | List authorization tuples with optional filtering                     |
| `WriteRelationships`  | `stream WriteRequest`      | `WriteResponse`                    | Write relationships (streaming API for single/batch operations)       |
| `DeleteRelationships` | `stream DeleteRequest`     | `DeleteResponse`                   | Delete relationships (streaming API for single/batch operations)      |
| `Watch`               | `WatchRequest`             | `stream WatchResponse`             | Stream real-time relationship change events                           |
| `Health`              | `HealthRequest`            | `HealthResponse`                   | Health check                                                          |

### REST/HTTP API

Defined in: `api/openapi.yaml`

| Method | Path                    | Purpose                                                  | Status         |
| ------ | ----------------------- | -------------------------------------------------------- | -------------- |
| `GET`  | `/health`               | Health check                                             | ✅ Implemented |
| `POST` | `/evaluate`             | Evaluate permissions (SSE stream, batch, optional trace) | ✅ Implemented |
| `POST` | `/simulate`             | Test authorization with ephemeral relationships          | ✅ Implemented |
| `POST` | `/expand`               | Expand relation (SSE stream)                             | ✅ Implemented |
| `POST` | `/list-resources`       | Lookup accessible resources (SSE stream)                 | ✅ Implemented |
| `POST` | `/list-subjects`        | Lookup subjects with access to resource (SSE stream)     | ✅ Implemented |
| `POST` | `/list-relationships`   | List authorization tuples (SSE stream)                   | ✅ Implemented |
| `POST` | `/write-relationships`  | Write tuples                                             | ✅ Implemented |
| `POST` | `/delete-relationships` | Delete tuples                                            | ✅ Implemented |
| `POST` | `/watch`                | Stream real-time relationship changes (SSE stream)       | ✅ Implemented |

### AuthZEN-Compliant API

InferaDB implements the OpenID Foundation's AuthZEN specification for authorization API interoperability.

**Discovery Endpoint:**

| Method | Path                                 | Purpose                            | Status         |
| ------ | ------------------------------------ | ---------------------------------- | -------------- |
| `GET`  | `/.well-known/authzen-configuration` | AuthZEN service discovery metadata | ✅ Implemented |

**Core AuthZEN Endpoints:**

| Method | Path                         | Purpose                                        | Status         |
| ------ | ---------------------------- | ---------------------------------------------- | -------------- |
| `POST` | `/access/v1/evaluation`      | Single authorization decision (AuthZEN format) | ✅ Implemented |
| `POST` | `/access/v1/evaluations`     | Batch authorization decisions (AuthZEN format) | ✅ Implemented |
| `POST` | `/access/v1/search/resource` | Find resources accessible by subject           | ✅ Implemented |
| `POST` | `/access/v1/search/subject`  | Find subjects with access to resource          | ✅ Implemented |

**InferaDB Extensions (Native `/v1/` API):**

All native InferaDB endpoints listed above (`/evaluate`, `/expand`, `/simulate`, etc.) are also available and provide additional features beyond AuthZEN core spec. The `.well-known/authzen-configuration` endpoint advertises these extensions:

- `inferadb_relationship_management: true` - Direct relationship CRUD operations
- `inferadb_relation_expansion: true` - Relation tree expansion
- `inferadb_simulation: true` - What-if testing with ephemeral relationships
- `inferadb_realtime_streaming: true` - Real-time change notifications

**REST Helper Endpoints:**

Convenience endpoints for exact relationship match operations:

| Method   | Path                                                | Purpose                                   | Status         |
| -------- | --------------------------------------------------- | ----------------------------------------- | -------------- |
| `GET`    | `/v1/relationships/{resource}/{relation}/{subject}` | Check if specific relationship exists     | ✅ Implemented |
| `DELETE` | `/v1/relationships/{resource}/{relation}/{subject}` | Delete specific relationship (idempotent) | ✅ Implemented |

**Account & Vault Management API:**

Multi-tenancy management endpoints for Accounts and Vaults:

| Method   | Path                              | Purpose                                    | Status         |
| -------- | --------------------------------- | ------------------------------------------ | -------------- |
| `POST`   | `/v1/accounts`                    | Create new account (admin only)            | ✅ Implemented |
| `GET`    | `/v1/accounts`                    | List all accounts (admin only)             | ✅ Implemented |
| `GET`    | `/v1/accounts/:id`                | Get account by ID (admin or owner)         | ✅ Implemented |
| `PATCH`  | `/v1/accounts/:id`                | Update account name (admin only)           | ✅ Implemented |
| `DELETE` | `/v1/accounts/:id`                | Delete account with cascade (admin only)   | ✅ Implemented |
| `POST`   | `/v1/accounts/:account_id/vaults` | Create vault for account (admin or owner)  | ✅ Implemented |
| `GET`    | `/v1/accounts/:account_id/vaults` | List vaults for account (admin or owner)   | ✅ Implemented |
| `GET`    | `/v1/vaults/:id`                  | Get vault by ID (admin or account owner)   | ✅ Implemented |
| `PATCH`  | `/v1/vaults/:id`                  | Update vault details (admin only)          | ✅ Implemented |
| `DELETE` | `/v1/vaults/:id`                  | Delete vault with cascade (admin or owner) | ✅ Implemented |

**Authorization Model:**

- **Admin scope** (`inferadb.admin`): Full access to all accounts and vaults
- **Account owners**: Can access their own account and its vaults
- **Cascade deletes**: Account deletion cascades to vaults, which cascade to relationships

**AuthZEN Compatibility:**

- Full compliance with AuthZEN 1.0 core specification
- Standard request/response formats with `{type, id}` entity structure
- Bidirectional conversion between AuthZEN format and InferaDB native format
- Extensions properly advertised via `.well-known/authzen-configuration`
- See `docs/api/authzen-mapping.md` for format conversion details

---

## Endpoint Comparison Matrix

| Capability                   | InferaDB                   | SpiceDB                  | OpenFGA                      | Oso                    | WorkOS FGA         | Cedar/AVP              |
| ---------------------------- | -------------------------- | ------------------------ | ---------------------------- | ---------------------- | ------------------ | ---------------------- |
| **Authorization Check**      | ✅ `Evaluate`              | ✅ `CheckPermission`     | ✅ `Check`                   | ✅ `authorize()`       | ✅ `check()`       | ✅ `IsAuthorized`      |
| **Batch Check**              | ✅ `Evaluate` (streaming)  | ⚠️ Pipeline              | ✅ `BatchCheck`              | ✅ `batchAuthorize()`  | ✅ `batch_check()` | ✅ `BatchIsAuthorized` |
| **Check with Trace/Debug**   | ✅ `Evaluate` (trace flag) | ⚠️ Logs only             | ⚠️ Basic                     | ✅ `debug_authorize()` | ❌                 | ❌                     |
| **Write Relationships**      | ✅ `WriteRelationships`    | ✅ `WriteRelationships`  | ✅ `Write`                   | ✅ `tell()`            | ✅ `WriteWarrant`  | ✅ `PutPolicy`         |
| **Batch Write**              | ✅ `WriteRelationships`    | ✅ Bulk import           | ✅ Batch                     | ✅ Batch               | ✅ Batch           | ✅ Batch               |
| **Delete Relationships**     | ✅ `DeleteRelationships`   | ✅ `DeleteRelationships` | ✅ `Delete`                  | ✅ `delete()`          | ✅ `DeleteWarrant` | ✅ `DeletePolicy`      |
| **Read/List Relationships**  | ✅ `ListRelationships`     | ✅ `ReadRelationships`   | ✅ `Read`                    | ✅ `get()`             | ✅ `ListWarrants`  | ✅ `GetPolicy`         |
| **Expand Relation**          | ✅ `Expand`                | ✅ `Expand`              | ✅ `Expand`                  | ❌                     | ❌                 | ❌                     |
| **Lookup Resources**         | ✅ `ListResources`         | ✅ `LookupResources`     | ✅ `ListObjects`             | ✅ `list()`            | ✅ `query()`       | ⚠️ Manual              |
| **Lookup Subjects**          | ✅ `ListSubjects`          | ✅ `LookupSubjects`      | ✅ `ListUsers`               | ✅ `list()`            | ✅ `query()`       | ⚠️ Manual              |
| **Watch/Stream Changes**     | ✅ `Watch`                 | ✅ `Watch`               | ✅ `Watch`                   | ❌                     | ❌                 | ❌                     |
| **Account/Vault Management** | ✅ REST API (Phase 4)      | ❌                       | ❌                           | ❌                     | ❌                 | ❌                     |
| **Schema Management**        | ⚠️ Manual                  | ✅ `WriteSchema`         | ✅ `WriteAuthorizationModel` | ✅ API                 | ✅ API             | ✅ `CreatePolicyStore` |
| **Health Check**             | ✅ `Health`                | ✅ gRPC Health           | ✅ gRPC Health               | ✅ `/health`           | ✅ `/health`       | ✅ AWS Health          |

**Legend:**

- ✅ = Fully implemented
- ⚠️ = Partially implemented or limited
- ❌ = Not implemented

---

## Detailed Endpoint Comparisons

### 1. Authorization Check

**Primary authorization endpoint - check if subject has permission on resource**

#### InferaDB

**Status**: ✅ **FULLY IMPLEMENTED** with streaming support for single and batch checks

**Design Decision**: InferaDB uses a **streaming-only Check API** for both single and batch operations. This simplifies the API surface while enabling efficient batch checking with progressive response streaming.

**gRPC (Bidirectional Streaming):**

```protobuf
rpc Evaluate(stream EvaluateRequest) returns (stream EvaluateResponse);

message EvaluateRequest {
  string subject = 1;      // e.g., "user:alice"
  string resource = 2;     // e.g., "doc:readme"
  string permission = 3;   // e.g., "can_view"
  optional string context = 4;  // Optional context for WASM
}

message EvaluateResponse {
  Decision decision = 1;    // ALLOW or DENY
  uint32 index = 2;         // Index of request (for batch operations)
  optional string error = 3;  // Error message if check failed
}
```

**REST (Server-Sent Events):**

```http
POST /evaluate
{
  "checks": [
    {
      "subject": "user:alice",
      "resource": "document:readme",
      "permission": "can_view",
      "context": { "ip_address": "192.168.1.1" }  // optional
    }
  ]
}

# Response (SSE stream):
data: {"decision":"allow","index":0}

event: summary
data: {"total":1,"complete":true}
```

**Batch Check Example:**

```http
POST /evaluate
{
  "checks": [
    {"subject": "user:alice", "resource": "doc:1", "permission": "reader"},
    {"subject": "user:alice", "resource": "doc:2", "permission": "reader"},
    {"subject": "user:alice", "resource": "doc:3", "permission": "reader"}
  ]
}

# Response (SSE stream - progressive results):
data: {"decision":"allow","index":0}

data: {"decision":"deny","index":1}

data: {"decision":"allow","index":2}

event: summary
data: {"total":3,"complete":true}
```

**Features:**

- **Single check**: Array of 1 check
- **Batch check**: Array of N checks (no hard limit, stream-based)
- **Progressive streaming**: Results returned as evaluated
- **Error handling**: Individual check errors don't fail entire batch
- **Index tracking**: Response index matches request index

**Performance**: <5ms simple checks, <20ms complex, ~50ms for batch of 50 checks

#### SpiceDB

**gRPC:**

```protobuf
rpc EvaluatePermission(CheckPermissionRequest) returns (CheckPermissionResponse);

message CheckPermissionRequest {
  Consistency consistency = 1;
  ObjectReference resource = 2;
  string permission = 3;
  SubjectReference subject = 4;
  map<string, ContextualTuples> context = 5;  // For caveats
}
```

**Key Differences:**

- SpiceDB uses structured `ObjectReference` and `SubjectReference` (separate namespace/object_id fields)
- InferaDB uses string format `type:id`
- SpiceDB has consistency control (minimize latency, full consistency, at-exact-snapshot)
- SpiceDB supports contextual tuples (relationships that exist only for this request)
- InferaDB context is for WASM modules only

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/check
{
  "tuple_key": {
    "user": "user:alice",
    "relation": "viewer",
    "object": "document:readme"
  },
  "contextual_tuples": []  // Optional
}
```

**Key Differences:**

- OpenFGA requires store_id in path (multi-tenancy)
- Uses `tuple_key` wrapper object
- InferaDB supports both gRPC and REST equally
- OpenFGA primarily REST-focused

#### Oso

**Python SDK:**

```python
result = await oso.authorize(
    actor="user:alice",
    action="view",
    resource="document:readme",
    context={"ip_address": "192.168.1.1"}
)
```

**HTTP:**

```http
POST /authorize
{
  "actor_type": "User",
  "actor_id": "alice",
  "action": "view",
  "resource_type": "Document",
  "resource_id": "readme",
  "context": {}
}
```

**Key Differences:**

- Oso separates type and ID (actor_type/actor_id)
- InferaDB uses colon format (type:id)
- Oso context is native (not WASM-only)
- Oso is SDK-first, API second

#### WorkOS FGA

**HTTP:**

```http
POST /warrant/check
{
  "warrants": [{
    "object_type": "document",
    "object_id": "readme",
    "relation": "viewer",
    "subject": {
      "object_type": "user",
      "object_id": "alice"
    }
  }]
}
```

**Key Differences:**

- Uses "warrant" terminology instead of "tuple"
- Nested subject object structure
- InferaDB simpler flat string format
- WorkOS is managed service (requires API key, usage-based pricing)

#### Cedar/AVP

**HTTP (via AWS SDK):**

```python
response = client.is_authorized(
    policyStoreId='ps-123',
    principal={
        'entityType': 'User',
        'entityId': 'alice'
    },
    action={
        'actionType': 'Action',
        'actionId': 'view'
    },
    resource={
        'entityType': 'Document',
        'entityId': 'readme'
    },
    context={
        'contextMap': {
            'ip_address': {'string': '192.168.1.1'}
        }
    }
)
```

**Key Differences:**

- Cedar is policy-based (not relationship-based like InferaDB)
- Requires typed context (must specify `{'string': value}`)
- InferaDB relationship model vs Cedar policy model
- Cedar supports native conditions, InferaDB requires WASM

---

### 2. Batch Authorization Check

**Check multiple permissions in one request**

#### InferaDB

**Status**: ✅ **FULLY IMPLEMENTED** (Phase 1.5)

InferaDB's streaming Check API natively supports batch operations - see Section 1 above for full details.

**Key Features:**

- **Unified API**: Same `/check` endpoint for single and batch operations
- **Progressive streaming**: Results returned as they're evaluated
- **No hard limits**: Stream-based approach handles any batch size
- **Robust error handling**: Individual check failures don't fail entire batch
- **Performance**: ~50ms for 50 checks (compared to ~500ms+ with N individual requests)

#### SpiceDB

**Workaround**: Use gRPC pipelining/multiplexing (not native batch)

```protobuf
// Must call CheckPermission N times
// Can pipeline over single connection
```

**Performance**: Can pipeline but still N evaluations

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/batch-check
{
  "checks": [
    {"user": "user:alice", "relation": "viewer", "object": "doc:1"},
    {"user": "user:alice", "relation": "viewer", "object": "doc:2"},
    {"user": "user:alice", "relation": "viewer", "object": "doc:3"}
  ]
}

Response:
{
  "results": [
    {"allowed": true},
    {"allowed": false},
    {"allowed": true}
  ]
}
```

**Limits**: Up to 100 checks per request

#### Oso

**Python SDK:**

```python
results = await oso.batchAuthorize([
    {"actor": "user:alice", "action": "view", "resource": "doc:1"},
    {"actor": "user:alice", "action": "view", "resource": "doc:2"},
    {"actor": "user:alice", "action": "view", "resource": "doc:3"}
])
```

**Returns**: List of boolean results matching input order

#### WorkOS FGA

**HTTP:**

```http
POST /warrant/batch-check
{
  "checks": [
    {"object_type": "document", "object_id": "1", "relation": "viewer", "subject": {"object_type": "user", "object_id": "alice"}},
    {"object_type": "document", "object_id": "2", "relation": "viewer", "subject": {"object_type": "user", "object_id": "alice"}}
  ]
}
```

#### Cedar/AVP

**AWS SDK:**

```python
response = client.batch_is_authorized(
    policyStoreId='ps-123',
    requests=[
        {'principal': {...}, 'action': {...}, 'resource': {...}},
        {'principal': {...}, 'action': {...}, 'resource': {...}}
    ]
)
```

**Limits**: Up to 30 requests per batch

**Key Insight**: InferaDB's streaming Check API provides **superior batch check capabilities** with no hard limits (competitors limit to 30-100 checks), progressive results, and the industry's **ONLY batch check + trace capability**.

---

### 3. Check with Trace/Debug

**Return evaluation trace for debugging**

#### InferaDB

**Status**: ✅ **Unified into Check API with optional trace flag**

**Design Decision**: InferaDB integrates tracing directly into the streaming Check API via an optional `trace` flag. This provides the industry's **ONLY batch check + detailed trace capability**.

**gRPC:**

```protobuf
rpc Evaluate(stream EvaluateRequest) returns (stream EvaluateResponse);

message EvaluateRequest {
  string subject = 1;
  string resource = 2;
  string permission = 3;
  optional string context = 4;
  optional bool trace = 5;  // Enable detailed trace
}

message EvaluateResponse {
  Decision decision = 1;
  uint32 index = 2;
  optional string error = 3;
  optional DecisionTrace trace = 4;  // Included when trace=true
}

message DecisionTrace {
  Decision decision = 1;
  EvaluationNode root = 2;
  Duration duration = 3;
  uint64 relationships_read = 4;
  uint64 relations_evaluated = 5;
}
```

**REST (Server-Sent Events):**

```http
POST /evaluate
{
  "checks": [{
    "subject": "user:alice",
    "resource": "doc:readme",
    "permission": "reader",
    "trace": true
  }]
}

# Response (SSE stream):
data: {"decision":"allow","index":0,"trace":{...}}

event: summary
data: {"total":1,"complete":true}
```

**Features:**

- **Unified API**: Same endpoint for production and debugging
- **Batch + Trace**: Only platform supporting detailed trace on batch checks
- **Complete evaluation tree** showing all nodes
- **Performance metrics** (duration, relationships read, relations evaluated)
- **Selective tracing**: Enable trace per-check in batch operations
- **Opt-in performance cost**: Trace only when needed

#### SpiceDB

**No dedicated trace endpoint**

Debugging via:

- Server logs (verbose mode)
- `--explain` flag in CLI tools
- No structured trace in API response

#### OpenFGA

**Partial support:**

```http
POST /stores/{store_id}/check?trace=true
```

Returns basic trace, but not as detailed as InferaDB

#### Oso

**Python SDK:**

```python
result = await oso.debug_authorize(
    actor="user:alice",
    action="view",
    resource="doc:readme"
)
# Returns evaluation trace
```

**HTTP**: `/debug/authorize` endpoint

#### WorkOS FGA

**No trace support** - Managed service, limited debugging

#### Cedar/AVP

**No structured trace** - Policy evaluation is opaque

**Key Insight**: InferaDB has the **most comprehensive trace/debug support** with optional trace flag integrated into Check API, supporting detailed metrics on both single and batch operations. InferaDB is the **ONLY platform** with batch check + detailed trace capability.

---

### 3A. Simulate Endpoint (What-If Testing)

**Test authorization with ephemeral relationships without persisting data**

#### InferaDB

**Status**: ✅ **FULLY IMPLEMENTED** (gRPC + REST)

**Design Decision**: InferaDB provides a dedicated Simulate API for "what-if" scenario testing. This allows developers to test authorization decisions with temporary relationships without modifying the actual authorization state.

**gRPC:**

```protobuf
rpc Simulate(SimulateRequest) returns (SimulateResponse);

message SimulateRequest {
  // Ephemeral relationships to use for this check (temporary context)
  repeated Relationship context_relationships = 1;

  // The check to evaluate against the ephemeral context
  SimulateCheck check = 2;
}

message SimulateCheck {
  string subject = 1;
  string resource = 2;
  string permission = 3;
  optional string context = 4;  // JSON string for WASM modules
}

message SimulateResponse {
  Decision decision = 1;
  uint64 context_relationships_count = 2;
}
```

**REST:**

```http
POST /simulate
{
  "context_relationships": [
    {"resource": "doc:secret", "relation": "viewer", "subject": "user:alice"},
    {"resource": "folder:confidential", "relation": "parent", "subject": "doc:secret"},
    {"resource": "folder:confidential", "relation": "owner", "subject": "user:bob"}
  ],
  "check": {
    "subject": "user:alice",
    "resource": "doc:secret",
    "permission": "viewer",
    "context": {"ip_address": "192.168.1.1"}  // optional
  }
}

Response:
{
  "decision": "allow",
  "context_relationships_count": 3
}
```

**How It Works:**

1. Creates an **ephemeral in-memory store** with ONLY the provided `context_relationships`
2. Runs the authorization check against this temporary data
3. Returns the decision without persisting anything to the main store
4. Temporary store is discarded after the request completes

**Features:**

- **Isolated testing**: Test authorization logic without affecting production data
- **What-if scenarios**: "What if we added this relationship?" questions
- **Schema validation testing**: Verify relationship configurations before deployment
- **Policy simulation**: Test changes to authorization rules before implementing
- **Zero side effects**: No writes to the actual store
- **Full evaluation**: Uses same evaluator logic as production checks

**Use Cases:**

- **Pre-deployment testing**: Test authorization changes before going live

    ```http
    # Test if making Alice an editor would grant her view access
    POST /simulate
    {
      "context_relationships": [
        {"resource": "doc:readme", "relation": "editor", "subject": "user:alice"}
      ],
      "check": {
        "subject": "user:alice",
        "resource": "doc:readme",
        "permission": "viewer"
      }
    }
    ```

- **Schema design validation**: Verify permission inheritance works as expected

    ```http
    # Test if folder ownership grants document access
    POST /simulate
    {
      "context_relationships": [
        {"resource": "folder:reports", "relation": "owner", "subject": "user:bob"},
        {"resource": "doc:annual_report", "relation": "parent", "subject": "folder:reports"}
      ],
      "check": {
        "subject": "user:bob",
        "resource": "doc:annual_report",
        "permission": "viewer"
      }
    }
    ```

- **Access control debugging**: Test complex relationship graphs
- **Integration testing**: Verify authorization behavior in test suites
- **Training/demos**: Show authorization scenarios without modifying real data

**Authentication:**

Requires `inferadb.simulate` scope

**Performance:**

Similar to regular Check operations (~5-20ms) plus minimal overhead for ephemeral store creation

**Limitations:**

- Context relationships are **only** available for this single check
- No access to relationships from the main store
- Cannot test Watch or streaming operations
- Not suitable for load testing (use regular Check API)

**Comparison to Contextual Tuples:**

Similar to SpiceDB's "contextual tuples" feature, but InferaDB provides:

- Dedicated endpoint for clarity
- Explicit ephemeral semantics
- No risk of accidentally mixing with production data

**Implementation:**

- **gRPC**: `crates/infera-api/src/grpc.rs:706-779` + proto definition in `crates/infera-api/proto/infera.proto:421-453`
- **REST**: `crates/infera-api/src/lib.rs:766-839`

#### Competitors

**SpiceDB**: Contextual tuples in `CheckPermissionRequest.context` field (mixed with regular checks)

**OpenFGA**: `contextual_tuples` parameter in Check API (mixed with regular checks)

**Oso**: No dedicated simulate endpoint (use regular check with temporary facts)

**WorkOS FGA**: No simulate capability

**Cedar/AVP**: No simulate endpoint (policy evaluation only)

**Key Insight**: InferaDB's dedicated `/simulate` endpoint provides **clearer separation** between testing and production checks compared to competitors' inline contextual tuple approaches.

---

### 4. Write Relationships/Tuples

**Create authorization relationships**

#### InferaDB

**Design Decision**: InferaDB uses a **streaming-only write API** for both single and batch operations. This simplifies the API surface while maintaining full flexibility. SDKs will provide ergonomic wrappers to hide streaming complexity from developers.

**gRPC:**

```protobuf
rpc WriteRelationships(stream WriteRequest) returns (WriteResponse);

message WriteRequest {
  repeated Relationship relationships = 1;
}

message Relationship {
  string resource = 1;  // "doc:readme"
  string relation = 2;  // "viewer"
  string subject = 3;   // "user:alice"
}
```

**REST:**

```http
POST /write-relationships
{
  "relationships": [
    {"resource": "doc:readme", "relation": "viewer", "subject": "user:alice"}
  ]
}
```

**Note**: The REST API interface is unchanged - it internally writes directly to storage. The gRPC API uses client streaming for both single writes and batch operations.

**Limits**: No hard limit on batch size (stream-based)

#### SpiceDB

**gRPC:**

```protobuf
rpc WriteRelationships(WriteRelationshipsRequest) returns (WriteRelationshipsResponse);

message WriteRelationshipsRequest {
  repeated RelationshipUpdate updates = 1;
  repeated Precondition preconditions = 2;  // Optional
}

message RelationshipUpdate {
  Operation operation = 1;  // CREATE, TOUCH, or DELETE
  Relationship relationship = 2;
}
```

**Key Differences:**

- SpiceDB supports preconditions (conditional writes)
- SpiceDB operations: CREATE (fail if exists), TOUCH (upsert), DELETE
- InferaDB: simpler write-only model

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/write
{
  "writes": {
    "tuple_keys": [
      {"user": "user:alice", "relation": "viewer", "object": "doc:readme"}
    ]
  },
  "deletes": {
    "tuple_keys": [...]  // Can write and delete in same request
  }
}
```

**Key Differences:**

- OpenFGA supports write + delete in single request
- InferaDB: separate endpoints

#### Oso

**Python SDK:**

```python
await oso.tell(
    "user:alice",
    "member",
    "group:engineers"
)
```

**HTTP:**

```http
POST /facts
{
  "name": "has_relation",
  "args": ["user:alice", "member", "group:engineers"]
}
```

#### WorkOS FGA

**HTTP:**

```http
POST /warrants
{
  "object_type": "document",
  "object_id": "readme",
  "relation": "viewer",
  "subject": {
    "object_type": "user",
    "object_id": "alice"
  }
}
```

#### Cedar/AVP

**AWS SDK:**

```python
response = client.put_policy(
    policyStoreId='ps-123',
    definition={
        'static': {
            'statement': 'permit(...) when {...};'
        }
    }
)
```

**Key Difference**: Cedar writes policies, not relationships (different paradigm)

---

### 5. Delete Relationships/Tuples

**Remove authorization relationships**

#### InferaDB

**Status**: ✅ **FULLY IMPLEMENTED**

Supports both exact tuple deletion and powerful filter-based bulk deletion.

**Design Decision**: InferaDB uses a **streaming API** for delete operations, enabling efficient batch deletions and consistent API design with `WriteRelationships`.

**gRPC:**

```protobuf
rpc DeleteRelationships(stream DeleteRequest) returns (DeleteResponse);

message DeleteRequest {
  optional DeleteFilter filter = 1;          // Filter for bulk deletion
  repeated Relationship relationships = 2;   // Exact relationships to delete
  optional uint32 limit = 3;                 // Safety limit (default: 1000)
}

message DeleteFilter {
  optional string resource = 1;  // Filter by resource (e.g., "doc:readme")
  optional string relation = 2;  // Filter by relation (e.g., "viewer")
  optional string subject = 3;   // Filter by subject (e.g., "user:alice")
}
```

**REST API:**

```http
POST /delete-relationships
{
  "filter": {
    "subject": "user:alice"  // Delete all relationships for a user
  }
}
```

**Capabilities:**

- **User offboarding**: Delete all relationships for a subject

    ```json
    { "filter": { "subject": "user:alice" } }
    ```

- **Resource cleanup**: Delete all relationships for a resource

    ```json
    { "filter": { "resource": "doc:deleted_document" } }
    ```

- **Relation cleanup**: Delete all relationships of a specific type

    ```json
    { "filter": { "relation": "viewer" } }
    ```

- **Combined filters**: Delete specific resource+relation combinations

    ```json
    { "filter": { "resource": "doc:readme", "relation": "viewer" } }
    ```

- **Exact deletion**: Delete specific relationships

    ```json
    {
        "relationships": [
            {
                "resource": "doc:1",
                "relation": "reader",
                "subject": "user:alice"
            }
        ]
    }
    ```

- **Combined mode**: Both filter and exact relationships
    ```json
    {
        "filter": { "subject": "user:alice" },
        "relationships": [
            {
                "resource": "doc:special",
                "relation": "owner",
                "subject": "user:bob"
            }
        ]
    }
    ```

**Safety Features:**

- Default limit of 1000 relationships for filter-based deletes
- Empty filter validation (at least one field required)
- Set `limit: 0` for unlimited deletion (use with caution!)

**Feature Parity**: Now matches SpiceDB's filtering capabilities

#### SpiceDB

**gRPC:**

```protobuf
rpc DeleteRelationships(DeleteRelationshipsRequest) returns (DeleteRelationshipsResponse);

message DeleteRelationshipsRequest {
  RelationshipFilter filter = 1;  // Powerful filtering
  repeated Precondition preconditions = 2;
  int32 limit = 3;  // Optional safety limit
}

message RelationshipFilter {
  string resource_type = 1;
  optional string resource_id = 2;
  optional string relation = 3;
  optional SubjectFilter subject_filter = 4;
}
```

**Capabilities:**

- Delete all relationships for a user: `subject_filter = {subject_type: "user", subject_id: "alice"}`
- Delete all viewers of a document: `resource_id = "readme", relation = "viewer"`
- Delete all relationships for a resource type
- Safety limits prevent accidental mass deletion

**Key Difference**: SpiceDB supports **filtering**, InferaDB only exact tuple deletion

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/write
{
  "deletes": {
    "tuple_keys": [
      {"user": "user:alice", "relation": "viewer", "object": "doc:readme"}
    ]
  }
}
```

**Also has dedicated delete:**

```http
DELETE /stores/{store_id}/tuples
```

**Limitation**: Must specify exact tuples (like InferaDB)

#### Oso

**Python SDK:**

```python
await oso.delete("user:alice", "member", "group:engineers")

# Batch delete
await oso.bulk_delete([
    ("user:alice", "member", "group:engineers"),
    ("user:bob", "member", "group:engineers")
])
```

**Supports filtering** via query patterns

#### WorkOS FGA

**HTTP:**

```http
DELETE /warrants/{warrant_id}

# Or batch
POST /warrants/delete
{
  "warrants": [
    {"object_type": "document", "object_id": "readme", "relation": "viewer", "subject": {...}}
  ]
}
```

#### Cedar/AVP

**AWS SDK:**

```python
response = client.delete_policy(
    policyStoreId='ps-123',
    policyId='policy-123'
)
```

**Key Insight**: InferaDB's delete now **matches SpiceDB's filtering capabilities** with comprehensive filter-based deletion. The streaming API enables efficient batch deletions for:

- User offboarding (delete all relationships for a subject)
- Resource cleanup (delete all relationships for a resource)
- Bulk delete by pattern (using filters)

---

### 6. Read/List Relationships

**Query existing relationships**

#### InferaDB

**Status**: ❌ **NOT IMPLEMENTED**

**Critical Gap**: Cannot inspect existing relationships

**Use cases blocked:**

- "Who has access to this document?"
- "What resources does Alice have access to?"
- Debugging authorization state
- Admin UIs
- Audit/compliance

#### SpiceDB

**gRPC:**

```protobuf
rpc ReadRelationships(ReadRelationshipsRequest) returns (stream ReadRelationshipsResponse);

message ReadRelationshipsRequest {
  Consistency consistency = 1;
  RelationshipFilter filter = 2;
  int32 limit = 3;
  Cursor cursor = 4;  // For pagination
}
```

**Example queries:**

```go
// All viewers of doc:readme
filter = {resource_type: "document", resource_id: "readme", relation: "viewer"}

// All Alice's relationships
filter = {subject_filter: {subject_type: "user", subject_id: "alice"}}

// All document relationships
filter = {resource_type: "document"}
```

**Features:**

- Streaming responses for large result sets
- Pagination with cursor
- Powerful filtering

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/read
{
  "tuple_key": {
    "user": "user:alice",      // Optional filter
    "relation": "viewer",      // Optional filter
    "object": "document:readme" // Optional filter
  },
  "page_size": 100,
  "continuation_token": "..."
}
```

**Features:**

- Pagination with continuation tokens
- Can filter by any combination of user/relation/object

#### Oso

**Python SDK:**

```python
# Get all facts matching pattern
facts = await oso.get("user:alice", "member", None)  # All groups Alice is member of

# Query pattern
facts = await oso.query("has_relation", ["user:alice", "member", "?group"])
```

**Features:**

- Pattern matching with variables
- Returns all matching facts

#### WorkOS FGA

**HTTP:**

```http
GET /warrants?objectType=document&objectId=readme&relation=viewer

# Or more advanced
POST /warrants/query
{
  "filters": {
    "object_type": "document",
    "relation": "viewer"
  }
}
```

**Features:**

- REST-style filtering via query params
- Pagination support

#### Cedar/AVP

**AWS SDK:**

```python
response = client.list_policies(
    policyStoreId='ps-123',
    maxResults=100,
    nextToken='...'
)
```

**Different paradigm**: Lists policies, not relationships

**Key Insight**: InferaDB is the ONLY platform without relationship read/query capability. This is **critical for administration and debugging**.

---

### 7. Expand Relation

**Show all users/subjects who have a permission and why**

#### InferaDB

**Status**: ✅ **Streaming-only for progressive results**

**Design Decision**: InferaDB uses a **streaming-only Expand API** for progressive user discovery and better performance with large usersets. This provides better scalability than competitors' buffered approaches.

**gRPC:**

```protobuf
rpc Expand(ExpandRequest) returns (stream ExpandResponse);

message ExpandRequest {
  string resource = 1;  // "doc:readme"
  string relation = 2;  // "viewer"
}

message ExpandResponse {
  oneof payload {
    string user = 1;              // Individual user (progressive)
    ExpandStreamSummary summary = 2;  // Final summary with tree
  }
}

message ExpandStreamSummary {
  UsersetTree tree = 1;      // Complete userset tree
  uint64 total_users = 2;    // Total count
}
```

**REST (Server-Sent Events):**

```http
POST /expand
{
  "resource": "doc:readme",
  "relation": "viewer"
}

# Response (SSE stream - progressive users):
data: {"subject":"user:alice","index":0}

data: {"subject":"user:bob","index":1}

event: summary
data: {"tree":{...},"total_count":2,"complete":true}
```

**Features:**

- **Progressive streaming**: Users returned as discovered
- **Complete userset tree**: Shows union/intersection/exclusion structure
- **Scalable**: No buffering, handles large usersets efficiently
- **SSE support**: Progressive rendering in web clients

#### SpiceDB

**gRPC:**

```protobuf
rpc Expand(ExpandRequest) returns (ExpandResponse);

message ExpandRequest {
  Consistency consistency = 1;
  ObjectReference subject = 2;
  int32 expansion_mode = 3;  // SHALLOW or RECURSIVE
}
```

**Features:**

- Shallow vs recursive expansion
- Consistency control

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/expand
{
  "tuple_key": {
    "relation": "viewer",
    "object": "document:readme"
  }
}
```

**Returns tree structure** similar to InferaDB

#### Oso

**No expand endpoint** - Different model (policy evaluation, not relationship graph)

#### WorkOS FGA

**No expand endpoint** - Managed service doesn't expose graph structure

#### Cedar/AVP

**No expand concept** - Policy-based, not relationship graph

**Key Insight**: InferaDB's expand with streaming is **superior to most competitors** for handling large usersets.

---

### 8. Lookup Resources (ListObjects)

**Find all resources a user can access**

#### InferaDB

**Status**: ✅ **IMPLEMENTED** (Phase 1.1 complete)

**Critical use case:** "What documents can Alice view?"

**gRPC:**

```protobuf
rpc ListResources(ListResourcesRequest) returns (stream ListResourcesResponse);

message ListResourcesRequest {
  string subject = 1;         // "user:alice"
  string resource_type = 2;   // "document"
  string permission = 3;      // "can_view"
  optional uint32 limit = 4;  // Max results per page
  optional string cursor = 5; // Pagination cursor
}

message ListResourcesResponse {
  string resource = 1;           // "document:readme"
  optional string cursor = 2;    // Continuation token (in final message)
  optional uint64 total_count = 3; // Resources checked (in final message)
}
```

**REST:**

```http
POST /list-resources
{
  "subject": "user:alice",
  "resource_type": "document",
  "permission": "can_view",
  "limit": 100  // optional
}

Response:
{
  "resources": ["document:readme", "document:guide"],
  "cursor": "eyJvZmZzZXQiOjEwMH0=",  // if more results
  "total_count": 2
}
```

**Streaming (SSE):**

```http
POST /list-resources
# Server-Sent Events (SSE) stream
data: {"resource":"document:readme","index":0}

data: {"resource":"document:guide","index":1}

event: summary
data: {"cursor":null,"total_count":2,"complete":true}
```

**Features:**

- Server-side streaming for large result sets (gRPC and SSE)
- Cursor-based pagination (base64-encoded)
- Efficient: Checks each resource using existing check() method
- Consistent with snapshot isolation via revision

**Performance**: Target <100ms for 10K resources

**Implementation**: evaluator.rs:953-1048, lib.rs:756-912, openapi.yaml:258-410

#### SpiceDB

**gRPC:**

```protobuf
rpc ListResources(ListResourcesRequest) returns (stream ListResourcesResponse);

message ListResourcesRequest {
  Consistency consistency = 1;
  string resource_object_type = 2;  // "document"
  string permission = 3;             // "view"
  SubjectReference subject = 4;      // user:alice
  Cursor cursor = 5;                 // Pagination
  int32 limit = 6;
}
```

**Features:**

- Streaming results
- Pagination
- Efficient graph traversal (O(log N))

**Example:**

```go
// "What documents can Alice view?"
req := &ListResourcesRequest{
    ResourceObjectType: "document",
    Permission: "view",
    Subject: &SubjectReference{
        Object: &ObjectReference{
            ObjectType: "user",
            ObjectId: "alice",
        },
    },
}
```

**Performance**: ~100ms for 10K resources, streaming for larger sets

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/list-objects
{
  "type": "document",
  "relation": "viewer",
  "user": "user:alice",
  "contextual_tuples": []  // optional
}

Response:
{
  "objects": ["document:1", "document:2", "document:3"]
}
```

**Features:**

- Type filtering
- Contextual tuples for what-if scenarios
- Efficient graph walk

#### Oso

**Python SDK:**

```python
# List all documents Alice can view
docs = await oso.list(
    actor="user:alice",
    action="view",
    resource_type="Document"
)
# Returns: ["document:1", "document:2", ...]
```

**HTTP:**

```http
POST /list
{
  "actor_type": "User",
  "actor_id": "alice",
  "action": "view",
  "resource_type": "Document"
}
```

**Features:**

- Native support
- Can handle 10K+ resources
- Optional context for filtering

#### WorkOS FGA

**HTTP (SQL-like query):**

```http
POST /warrant/query
{
  "q": "SELECT warrant WHERE subject = 'user:alice' AND relation = 'viewer' AND objectType = 'document'"
}
```

**Features:**

- SQL-like query language (unique to WorkOS)
- Very flexible
- Returns matching warrants

**Alternative simpler endpoint:**

```http
GET /warrants/query-graph
  ?subject=user:alice
  &relation=viewer
  &objectType=document
```

#### Cedar/AVP

**No native support** - Must manually iterate

Workaround:

```python
# Must check each resource individually
for resource in all_resources:
    result = client.is_authorized(
        principal={'entityType': 'User', 'entityId': 'alice'},
        action={'actionType': 'Action', 'actionId': 'view'},
        resource={'entityType': 'Document', 'entityId': resource.id}
    )
    if result['decision'] == 'ALLOW':
        accessible.append(resource)
```

**Performance**: O(N) checks - very inefficient

**Key Insight**: InferaDB missing this is a **SHOWSTOPPER**. This is the #1 most common authorization query in production systems.

**Competitive advantage lost**: All competitors except Cedar have this. Cedar is different paradigm, so acceptable they don't have it.

---

### 9. Lookup Subjects (ListUsers)

**Find all users who have access to a resource**

#### InferaDB

**Status**: ✅ **IMPLEMENTED** (Phase 2.1 complete)

**Critical use case:** "Who can view this document?"

**gRPC:**

```protobuf
rpc ListSubjects(ListSubjectsRequest) returns (stream ListSubjectsResponse);

message ListSubjectsRequest {
  string resource = 1;          // "document:readme"
  string relation = 2;          // "viewer"
  optional string subject_type = 3; // Filter by type (e.g., "user")
  optional uint32 limit = 4;    // Max results per page
  optional string cursor = 5;   // Pagination cursor
}

message ListSubjectsResponse {
  string subject = 1;           // "user:alice"
  optional string cursor = 2;   // Continuation token (in final message)
  optional uint64 total_count = 3; // Total subjects (in final message)
}
```

**REST:**

```http
POST /list-subjects
{
  "resource": "document:readme",
  "relation": "viewer",
  "subject_type": "user"  // optional
}

Response:
{
  "subjects": ["user:alice", "user:bob"],
  "total_count": 2
}
```

**Streaming (SSE):**

```http
POST /list-subjects
# Server-Sent Events (SSE) stream
data: {"subject":"user:alice","index":0}

data: {"subject":"user:bob","index":1}

event: summary
data: {"cursor":null,"total_count":2,"complete":true}
```

**Features:**

- Server-side streaming for large result sets (gRPC and SSE)
- Cursor-based pagination (base64-encoded)
- Subject type filtering (e.g., "user", "group")
- Reverse graph traversal with deduplication
- Handles complex relations (Union, Intersection, Exclusion, RelatedObjectUserset, ComputedUserset)
- Consistent with snapshot isolation via revision

**Performance**: Target <50ms for 1K subjects, <500ms for 10K subjects

**Implementation**: evaluator.rs:1390-1738, grpc.rs (ListSubjects handler), lib.rs (list_subjects_stream_handler), openapi.yaml:539-697

**Enables:**

- Access control admin panels
- "Share with" dialogs showing who has access
- Compliance reports
- Audit logs
- Access review workflows

#### SpiceDB

**gRPC:**

```protobuf
rpc LookupSubjects(LookupSubjectsRequest) returns (stream LookupSubjectsResponse);

message LookupSubjectsRequest {
  Consistency consistency = 1;
  ObjectReference resource = 2;     // document:readme
  string permission = 3;             // view
  string subject_object_type = 4;    // user
  Cursor cursor = 5;
}
```

**Example:**

```go
// "Who can view document:readme?"
req := &LookupSubjectsRequest{
    Resource: &ObjectReference{
        ObjectType: "document",
        ObjectId: "readme",
    },
    Permission: "view",
    SubjectObjectType: "user",
}
```

**Returns**: Stream of user IDs

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/list-users
{
  "object": {
    "type": "document",
    "id": "readme"
  },
  "relation": "viewer",
  "user_filters": [
    {"type": "user"}
  ]
}

Response:
{
  "users": [
    {"object": {"type": "user", "id": "alice"}},
    {"object": {"type": "user", "id": "bob"}}
  ]
}
```

**Features:**

- Filter by user type
- Pagination

#### Oso

**Python SDK:**

```python
# List all users who can view doc:readme
users = await oso.list(
    resource="document:readme",
    action="view",
    actor_type="User"
)
# Returns: ["user:alice", "user:bob", ...]
```

**Note**: Oso's `list()` works in both directions:

- List resources for actor
- List actors for resource

#### WorkOS FGA

**HTTP:**

```http
POST /warrant/query
{
  "q": "SELECT subject WHERE object = 'document:readme' AND relation = 'viewer' AND subjectType = 'user'"
}
```

**Returns**: List of users

#### Cedar/AVP

**No native support** - Would need to check each user individually (very inefficient)

**Key Insight**: InferaDB missing this blocks **administrative and compliance** use cases. Less critical than ListResources but still important.

---

### 10. Watch API (Stream Changes)

**Stream relationship changes in real-time**

#### InferaDB

**Status**: ✅ **FULLY IMPLEMENTED** with gRPC and REST/SSE streaming

**Design Decision**: InferaDB implements Watch API using both gRPC server streaming and REST Server-Sent Events (SSE), providing real-time change event delivery with efficient polling and backpressure handling.

**gRPC (Server Streaming):**

```protobuf
rpc Watch(WatchRequest) returns (stream WatchResponse);

message WatchRequest {
  repeated string resource_types = 1;  // Filter by resource type (e.g., ["document", "folder"])
  optional string cursor = 2;          // Base64-encoded revision to resume from
}

message WatchResponse {
  ChangeOperation operation = 1;       // CREATE or DELETE
  Relationship relationship = 2;        // The relationship that changed
  string revision = 3;                 // Revision at which change occurred
  string timestamp = 4;                // ISO 8601 timestamp
}

enum ChangeOperation {
  CHANGE_OPERATION_UNSPECIFIED = 0;
  CHANGE_OPERATION_CREATE = 1;
  CHANGE_OPERATION_DELETE = 2;
}
```

**REST/HTTP (SSE):**

```http
POST /watch
Content-Type: application/json

{
  "resource_types": ["document"],
  "cursor": "eyJyZXZpc2lvbiI6MTIzfQ=="  // Optional: resume from revision
}

# Server-Sent Events stream response
event: change
data: {"operation":"create","relationship":{"resource":"document:readme","relation":"viewer","subject":"user:alice"},"revision":"123","timestamp":"2024-01-15T10:30:00Z"}

event: change
data: {"operation":"delete","relationship":{"resource":"document:readme","relation":"editor","subject":"user:bob"},"revision":"124","timestamp":"2024-01-15T10:30:01Z"}

event: error
data: {"error":"Failed to read changes: database error"}
```

**Features:**

- ✅ **Real-time streaming** - Change events delivered with <100ms typical latency
- ✅ **Resource type filtering** - Watch specific resource types (e.g., ["document", "folder"])
- ✅ **Cursor-based resumption** - Resume from specific revision after reconnect
- ✅ **Both protocols** - gRPC for services, SSE for web clients
- ✅ **Efficient polling** - Backpressure handling with 100ms sleep when idle
- ✅ **Error handling** - Stream errors sent as events, then connection closes

**Change Log Storage:**

- **Memory Backend**: BTreeMap ordered by revision for efficient range queries
- **FoundationDB Backend**: Subspace with revision-based keys for durability
- **Automatic Capture**: Write/Delete operations automatically append to change log

**Use cases enabled:**

- ✅ **Real-time cache invalidation** - Invalidate permission caches when relationships change
- ✅ **Audit log streaming** - Stream all authorization changes to audit systems
- ✅ **Webhooks/notifications** - Trigger webhooks on permission changes
- ✅ **Event-driven authorization** - React to permission changes in real-time
- ✅ **Monitoring & compliance** - Track relationship changes for analytics

**Example (gRPC):**

```rust
// Watch for document changes and invalidate cache
let watch_req = WatchRequest {
    resource_types: vec!["document".to_string()],
    cursor: None,
};

let mut stream = client.watch(watch_req).await?.into_inner();

while let Some(event) = stream.next().await {
    let event = event?;
    match event.operation() {
        ChangeOperation::Create => {
            // Invalidate cache for created relationship
            cache.invalidate(&event.relationship);
        }
        ChangeOperation::Delete => {
            // Invalidate cache for deleted relationship
            cache.invalidate(&event.relationship);
        }
        _ => {}
    }
}
```

**Example (REST/SSE):**

```javascript
// Watch for all changes via Server-Sent Events
const eventSource = new EventSource("/watch", {
    method: "POST",
    body: JSON.stringify({ resource_types: [] }),
});

eventSource.addEventListener("change", (event) => {
    const change = JSON.parse(event.data);
    console.log(
        `${change.operation} ${change.relationship.resource}:${change.relationship.relation}`
    );

    // Invalidate local cache
    cache.invalidate(change.relationship);
});

eventSource.addEventListener("error", (event) => {
    const error = JSON.parse(event.data);
    console.error("Watch error:", error);
});
```

#### SpiceDB

**gRPC:**

```protobuf
rpc Watch(WatchRequest) returns (stream WatchResponse);

message WatchRequest {
  repeated string object_types = 1;  // Filter by type
  ZedToken start_revision = 2;       // Start watching from revision
}

message WatchResponse {
  repeated RelationshipUpdate updates = 1;
  ZedToken revision = 2;
  string change_type = 3;  // CREATED, DELETED, TOUCHED
}
```

**Features:**

- Watch all changes or filter by type
- Start from specific revision
- Streaming response

**Use case:**

```go
// Invalidate cache when permissions change
stream := client.Watch(ctx, &WatchRequest{
    ObjectTypes: []string{"document"},
    StartRevision: lastSeenRevision,
})

for {
    resp, err := stream.Recv()
    // Invalidate cache for affected resources
    cache.Invalidate(resp.Updates)
}
```

#### OpenFGA

**HTTP (SSE):**

```http
GET /stores/{store_id}/changes/watch?type=document

# Server-Sent Events stream
data: {"tuple_key": {...}, "operation": "WRITE", "timestamp": "..."}
data: {"tuple_key": {...}, "operation": "DELETE", "timestamp": "..."}
```

**Features:**

- SSE (Server-Sent Events) for HTTP streaming
- Filter by object type
- Timestamp for ordering

#### Oso

**Status**: ❌ No watch API

**Workaround**: Poll `/facts` endpoint

#### WorkOS FGA

**Status**: ⚠️ Has webhooks, not streaming

**HTTP:**

```http
POST /webhooks
{
  "url": "https://myapp.com/webhook",
  "events": ["warrant.created", "warrant.deleted"]
}
```

**Features:**

- Webhook notifications on changes
- Not real-time streaming
- Requires public endpoint

#### Cedar/AVP

**Status**: ❌ No watch API (managed service, no streaming)

**Key Insight**: InferaDB, SpiceDB, and OpenFGA all provide true streaming Watch APIs. WorkOS provides webhook-based notifications (not real-time streaming). Oso and Cedar/AVP have no Watch capability, requiring polling for change detection.

---

### 11. Schema Management

**Define and update authorization schemas**

#### InferaDB

**Status**: ⚠️ **MANUAL DEPLOYMENT**

Currently schemas are defined in `.ipl` files and loaded at startup.

**No runtime schema API** - must redeploy service

#### SpiceDB

**gRPC:**

```protobuf
rpc WriteSchema(WriteSchemaRequest) returns (WriteSchemaResponse);
rpc ReadSchema(ReadSchemaRequest) returns (ReadSchemaResponse);

message WriteSchemaRequest {
  string schema = 1;  // .zed schema definition
}
```

**Features:**

- Update schema at runtime
- Schema versioning
- Validate schema before applying

**Example:**

```go
resp := client.WriteSchema(ctx, &WriteSchemaRequest{
    Schema: `
        definition document {
            relation viewer: user
            relation editor: user
            permission can_view = viewer + editor
        }
    `,
})
```

#### OpenFGA

**HTTP:**

```http
POST /stores/{store_id}/authorization-models
{
  "type_definitions": [
    {
      "type": "document",
      "relations": {
        "viewer": {"this": {}},
        "editor": {"this": {}}
      }
    }
  ]
}

# Read current schema
GET /stores/{store_id}/authorization-models/{model_id}
```

**Features:**

- Multiple schema versions per store
- Schema validation
- Migration support

#### Oso

**HTTP:**

```http
# Upload policy file
POST /policy
{
  "filename": "policy.polar",
  "content": "allow(...) if ..."
}

# List policies
GET /policies
```

**Features:**

- Policy upload via API
- Multiple policy files
- Hot reload

#### WorkOS FGA

**HTTP:**

```http
# Schema is inferred from warrants
# Or use predefined templates
POST /resource-types
{
  "type": "document",
  "relations": ["viewer", "editor"]
}
```

#### Cedar/AVP

**AWS SDK:**

```python
# Create policy store with schema
response = client.create_policy_store(
    validationSettings={
        'mode': 'STRICT',
        'schema': {
            'cedarJson': '...'
        }
    }
)

# Update schema
response = client.put_schema(
    policyStoreId='ps-123',
    definition={'cedarJson': '...'}
)
```

**Features:**

- Schema validation (STRICT or OFF)
- JSON schema format
- Type checking

**Key Insight**: InferaDB needs runtime schema management API for production use. Competitors all support dynamic schema updates.

---

### 12. Health Check

**Service health and readiness**

#### InferaDB

**gRPC:**

```protobuf
rpc Health(HealthRequest) returns (HealthResponse);

message HealthResponse {
  string status = 1;   // "healthy"
  string service = 2;  // "InferaDB"
}
```

**REST:**

```http
GET /health

Response:
{
  "status": "healthy",
  "version": "0.1.0"
}
```

**Simple health check** - just up/down status

#### SpiceDB

**gRPC Health Check Protocol (standard):**

```protobuf
service Health {
  rpc Evaluate(HealthEvaluateRequest) returns (HealthEvaluateResponse);
  rpc Watch(HealthEvaluateRequest) returns (stream HealthEvaluateResponse);
}
```

**Features:**

- Standard gRPC health checking
- Watch for status changes
- Per-service health

#### OpenFGA

**HTTP:**

```http
GET /healthz

Response: 200 OK (healthy) or 503 Service Unavailable
```

**Simple readiness check**

#### Oso

**HTTP:**

```http
GET /health

Response:
{
  "status": "ok",
  "version": "1.2.3"
}
```

#### WorkOS FGA / Cedar

**Managed services** - health checks handled by cloud provider (AWS health checks, etc.)

**Key Insight**: All platforms have basic health checks. InferaDB's is standard.

---

## Missing Endpoints

### Critical Missing Endpoints (P0)

These endpoints are present in **ALL or MOST** competitors but missing in InferaDB:

#### 1. **ListResources / ListObjects** ✅ IMPLEMENTED (Phase 1.1)

**Present in:** InferaDB, SpiceDB, OpenFGA, Oso, WorkOS FGA (5/5 competitors)

**What it does:** Returns all resources a user can access

**InferaDB implementation:** ✅ ListResources (gRPC + REST)

**Status:** ✅ Fully implemented in Phase 1.1

**Implementation details:**

- **gRPC**: `ListResources` RPC (infera.proto:32, grpc.rs:352-409)
- **REST**: `POST /list-resources` (SSE streaming-only) (lib.rs:756-912)
- **Core logic**: evaluator.rs:953-1048
- **Storage**: list_objects_by_type trait method (lib.rs:89, memory.rs:265-297, foundationdb.rs:390-449)
- **OpenAPI**: openapi.yaml:258-410
- **Tests**: 6 unit tests in evaluator.rs:2284-2534, 4 REST tests in lib.rs:1585-1868

**Features:**

- Server-side streaming (gRPC + SSE)
- Cursor-based pagination
- Snapshot isolation for consistency
- Efficient checking using existing check() method

**Performance:** Target <100ms for 10K resources (achieved)

---

#### 2. **ReadRelationships / Read / ListWarrants** ✅ IMPLEMENTED

**Present in:** SpiceDB, OpenFGA, Oso, WorkOS FGA, Cedar (5/5 competitors)

**What it does:** Query existing authorization relationships

**InferaDB equivalent:** ✅ `ListRelationships` (gRPC + REST with streaming support)

**Competitors' names:**

- **SpiceDB**: `ReadRelationships`
- **OpenFGA**: `Read` (`POST /stores/{store_id}/read`)
- **Oso**: `get()` (`GET /facts`)
- **WorkOS FGA**: `ListWarrants` (`GET /warrants`)
- **Cedar/AVP**: `GetPolicy` / `ListPolicies`

**Example queries:**

- "List all viewers of document:readme"
- "List all permissions for user:alice"
- "Show all relationships of type 'document'"

**Why critical:** Cannot debug, cannot build admin UIs, cannot audit

**Implementation approach:**

```protobuf
// IMPLEMENTED in InferaDB as ListRelationships
rpc ListRelationships(ListRelationshipsRequest) returns (stream ListRelationshipsResponse);

message ListRelationshipsRequest {
  optional string resource = 1;    // Filter by resource (e.g., "doc:readme")
  optional string relation = 2;    // Filter by relation (e.g., "viewer")
  optional string subject = 3;     // Filter by subject (e.g., "user:alice")
  optional uint32 limit = 4;       // Max results
  optional string cursor = 5;      // Pagination cursor
}

message Relationship {
  string resource = 1;     // The resource (API-friendly naming)
  string relation = 2;     // The relation
  string subject = 3;      // The subject (API-friendly naming)
}

message ListRelationshipsResponse {
  Relationship relationship = 1;   // Single relationship (streamed)
  optional string cursor = 2;      // Continuation token (in final message)
  optional uint64 total_count = 3; // Total count (in final message)
}
```

---

#### 3. **DeleteRelationships (with filtering)** ✅ IMPLEMENTED

**Present in:** SpiceDB (filtering), OpenFGA (exact), Oso (filtering), WorkOS (exact), Cedar (5/5)

**InferaDB status:** ✅ **FULLY IMPLEMENTED** with streaming API

InferaDB now supports comprehensive filter-based deletion with a streaming API:

```protobuf
rpc DeleteRelationships(stream DeleteRequest) returns (DeleteResponse);

message DeleteRequest {
  optional DeleteFilter filter = 1;          // Filter for bulk deletion
  repeated Relationship relationships = 2;   // Exact relationships to delete
  optional uint32 limit = 3;                 // Safety limit (default: 1000)
}

message DeleteFilter {
  optional string resource = 1;  // Filter by resource
  optional string relation = 2;  // Filter by relation
  optional string subject = 3;   // Filter by subject
}
```

**Capabilities:**

- User offboarding: `{ filter: { subject: "user:alice" } }`
- Resource cleanup: `{ filter: { resource: "doc:deleted" } }`
- Relation cleanup: `{ filter: { relation: "viewer" } }`
- Combined filters: `{ filter: { resource: "doc:readme", relation: "viewer" } }`
- Exact deletion: `{ relationships: [...] }`
- Batch operations via streaming

**Status:** Feature parity with SpiceDB achieved

---

#### 4. **BatchCheck / BatchAuthorize** ✅ IMPLEMENTED

**Present in:** InferaDB, OpenFGA, Oso, WorkOS FGA, Cedar (5/5 competitors)

**What it does:** Check multiple permissions in one API call

**InferaDB implementation:** ✅ **Streaming Check API** (Phase 1.5)

**Status:** ✅ Fully implemented via streaming Check endpoint

**Competitors' implementations:**

- **SpiceDB**: ⚠️ No native batch, use pipelining
- **OpenFGA**: `BatchCheck` (`POST /stores/{store_id}/batch-check`)
- **Oso**: `batchAuthorize()`
- **WorkOS FGA**: `batch_check()` (`POST /warrant/batch-check`)
- **Cedar/AVP**: `BatchIsAuthorized` (up to 30 requests)
- **InferaDB**: `Evaluate` streaming API (SSE + gRPC streams)

**Performance:**

```
# Evaluate if Alice can view 50 documents

## InferaDB (streaming batch):
POST /evaluate (50 checks in array) → ~50ms total (SSE stream)

## OpenFGA (batch):
POST /batch-check (50 checks) → ~50ms total

## Without BatchCheck:
50 × POST /evaluate → ~500ms+ total (10x slower)
```

**InferaDB advantages:**

- **No hard limits**: Stream-based (competitors limit to 30-100 checks)
- **Progressive results**: See results as they're evaluated
- **Unified API**: Same endpoint for single and batch (simpler)
- **Robust errors**: Individual failures don't fail batch

**Implementation:**

```protobuf
// IMPLEMENTED in InferaDB
rpc Evaluate(stream EvaluateRequest) returns (stream EvaluateResponse);

message EvaluateRequest {
  string subject = 1;
  string resource = 2;
  string permission = 3;
  optional string context = 4;
}

message EvaluateResponse {
  Decision decision = 1;
  uint32 index = 2;         // Matches request index
  optional string error = 3;  // Per-check error handling
}
```

---

#### 5. **Native ABAC / Conditions** ⚠️ CRITICAL

**Present in:** SpiceDB (CEL), OpenFGA (CEL), Oso (native), WorkOS (native), Cedar (native) (5/5)

**InferaDB current:** ⚡ WASM only (complex, requires Rust expertise)

**Competitors' approaches:**

**SpiceDB (CEL):**

```
caveat business_hours(current_time timestamp) {
  current_time.getHours() >= 9 && current_time.getHours() < 17
}

definition document {
  relation viewer: user with business_hours
}
```

**OpenFGA (CEL):**

```json
{
    "type": "document",
    "relations": {
        "viewer": {
            "this": {},
            "condition": "time.now() > datetime('2024-01-01T00:00:00Z')"
        }
    }
}
```

**InferaDB (WASM - much harder):**

```rust
// Must write Rust code
#[no_mangle]
pub extern "C" fn check_business_hours() -> i32 {
    // 50+ lines of time checking logic
    // Must compile to WASM
    // Must deploy .wasm file
}
```

**Why critical:** Common ABAC scenarios (time-based access, IP filtering, attribute comparison) are much harder in InferaDB

**Implementation needed:** Add native conditions to IPL (while keeping WASM for advanced cases)

**Proposed syntax:**

```ipl
type document {
    relation viewer: user
    relation can_view = viewer
      when {
        context.time > datetime("2024-01-01T00:00:00Z") &&
        context.ip in ipaddr("192.168.0.0/16")
      }
}
```

---

### Major Missing Endpoints (P1)

#### 6. **LookupSubjects / ListUsers** ✅ IMPLEMENTED (Phase 2.1)

**Present in:** InferaDB, SpiceDB, OpenFGA, Oso, WorkOS FGA (5/5 competitors)

**What it does:** Returns all subjects with access to a resource

**InferaDB implementation:** ✅ ListSubjects (gRPC + REST)

**Status:** ✅ Fully implemented in Phase 2.1

**Implementation details:**

- **gRPC**: `ListSubjects` RPC (infera.proto:29-30, grpc.rs ListSubjects handler)
- **REST**: `POST /list-subjects` (SSE streaming) (lib.rs list_subjects_stream_handler)
- **Core logic**: evaluator.rs:1390-1738 (reverse graph traversal with deduplication)
- **OpenAPI**: openapi.yaml:539-697
- **Tests**: 12 unit tests in evaluator.rs (test_list_subjects_basic, test_list_subjects_with_computed_userset, test_list_subjects_with_union_relation, etc.)

**Features:**

- Server-side streaming (gRPC + SSE)
- Subject type filtering
- Cursor-based pagination
- Reverse graph traversal supporting all relation types
- Deduplication of subjects with multiple access paths
- Snapshot isolation for consistency

**Competitors:**

- **SpiceDB**: `LookupSubjects`
- **OpenFGA**: `ListUsers` (`POST /stores/{store_id}/list-users`)
- **Oso**: `list()` (reverse direction)
- **WorkOS FGA**: `query()` with reverse filter

---

#### 7. **Watch / Stream Changes**

**Present in:** SpiceDB, OpenFGA (2/5)

**What it does:** Stream relationship changes in real-time

**Competitors:**

- **SpiceDB**: `Watch` (gRPC streaming)
- **OpenFGA**: `GET /changes/watch` (SSE)

**Use cases:** Cache invalidation, audit logs, event-driven systems

---

### Nice-to-Have Endpoints (P2)

#### 8. **Schema Management APIs**

**Current:** Manual .ipl file deployment

**Needed:** Runtime schema updates

**Competitors:**

- **SpiceDB**: `WriteSchema`, `ReadSchema`
- **OpenFGA**: `POST /authorization-models`
- **Oso**: `POST /policy`

---

#### 9. **BulkImport / BulkExport**

**Present in:** SpiceDB (experimental), Oso (2/5)

**What it does:** Efficient bulk data operations

**Use cases:** Migration, backup/restore, initial data load

---

#### 10. **Wildcards / Public Access**

**Present in:** SpiceDB, OpenFGA, WorkOS FGA, **InferaDB** (4/5)

**Status:** ✅ **IMPLEMENTED** (Phase 3.1)

**What it does:** Model "all users" or "public" access using wildcard subjects

**InferaDB Implementation:**

Wildcards in InferaDB follow the `type:*` pattern in the subject field of relationships, representing "all entities of that type".

**Syntax:**

- `user:*` = all users
- `group:*` = all groups
- `service:*` = all services

**Constraints:**

- Wildcards are **only allowed in the subject position**
- Wildcards must be in the exact format `type:*`
- Wildcards in resource or relation fields are rejected with validation errors

**Authorization Behavior:**
When evaluating permissions, InferaDB automatically checks both:

1. Exact subject matches (e.g., `user:alice`)
2. Wildcard matches for the subject's type (e.g., `user:*`)

**Example:**

```
# Write a wildcard relationship - all users can view
POST /write-relationships
{
  "relationships": [
    {
      "resource": "document:public_readme",
      "relation": "viewer",
      "subject": "user:*"
    }
  ]
}

# Check authorization - any user will be allowed
POST /evaluate
{
  "subject": "user:alice",     # Will match user:*
  "resource": "document:public_readme",
  "permission": "viewer"
}
# Result: Allow

POST /evaluate
{
  "subject": "user:bob",       # Will also match user:*
  "resource": "document:public_readme",
  "permission": "viewer"
}
# Result: Allow

POST /evaluate
{
  "subject": "group:admins",   # Will NOT match user:* (different type)
  "resource": "document:public_readme",
  "permission": "viewer"
}
# Result: Deny
```

**Use Cases:**

1. **Public Resources**: Documents that all users can read
2. **Universal Permissions**: Features available to all entities of a type
3. **Default Access**: New resources that should be accessible to everyone
4. **Type-scoped Wildcards**: Different access levels for different entity types

**Performance:**

- Wildcard checks are performed in parallel with exact checks
- No performance degradation for regular (non-wildcard) queries
- Wildcards are stored and indexed like regular relationships

**Last Updated:** 2025-10-31

---

#### 11. **gRPC Server Reflection**

**Present in:** SpiceDB, Cedar (2/5)

**What it does:** Enables grpcui/grpcurl without proto files

**Impact:** Better developer experience for testing

---

## Summary

### InferaDB Current API Surface

**Implemented (22 endpoints + 1 feature):**

**Core Authorization Endpoints:**

- ✅ Check (streaming for single/batch operations with optional trace - Phase 1.5)
- ✅ Simulate (REST-only what-if testing with ephemeral relationships)
- ✅ Expand (streaming-only for progressive results)
- ✅ ListResources (Phase 1.1 - gRPC + REST + SSE streaming)
- ✅ ListSubjects (Phase 2.1 - gRPC + REST + SSE streaming with reverse graph traversal)
- ✅ ListRelationships (Phase 1.2 - gRPC + REST + SSE streaming with resource/subject naming)
- ✅ WriteRelationships (streaming API for single/batch writes)
- ✅ DeleteRelationships (streaming API with filter-based and exact deletion)
- ✅ Watch (Phase 2.2 - gRPC + REST/SSE streaming for real-time change events)
- ✅ Health

**Account & Vault Management (Phase 4):**

- ✅ POST /v1/accounts - Create account (admin only)
- ✅ GET /v1/accounts - List accounts (admin only)
- ✅ GET /v1/accounts/:id - Get account (admin or owner)
- ✅ PATCH /v1/accounts/:id - Update account (admin only)
- ✅ DELETE /v1/accounts/:id - Delete account with cascade (admin only)
- ✅ POST /v1/accounts/:account_id/vaults - Create vault (admin or owner)
- ✅ GET /v1/accounts/:account_id/vaults - List vaults (admin or owner)
- ✅ GET /v1/vaults/:id - Get vault (admin or account owner)
- ✅ PATCH /v1/vaults/:id - Update vault (admin only)
- ✅ DELETE /v1/vaults/:id - Delete vault with cascade (admin or owner)

**Features:**

- ✅ **Wildcards / Public Access** (Phase 3.1 - `type:*` pattern for universal permissions)

**Critical Gaps (1 endpoint):**

- ⚠️ Native ABAC conditions (CRITICAL - 5/5 competitors, InferaDB WASM-only)

**Nice-to-Have (3 endpoints):**

- ❌ Schema management API
- ❌ BulkImport/Export
- ❌ gRPC reflection

### Competitive Position

**Where InferaDB Leads:**

- ✅ **Check API** - Unified streaming API for single/batch with optional trace, no hard limits (competitors limit 30-100)
- ✅ **Batch Check + Trace** - Industry's ONLY platform with detailed trace on batch checks (unique competitive advantage)
- ✅ **Simulate Endpoint** - Dedicated REST endpoint for what-if testing with ephemeral relationships (clearer than competitors' inline contextual tuples)
- ✅ **Expand API** - Streaming-only for progressive results (competitors buffer all users)
- ✅ **WriteRelationships** - Unified streaming API for single/batch writes (simpler API surface)
- ✅ **DeleteRelationships** - Streaming API with comprehensive filter-based deletion (matches SpiceDB's capabilities)

**Where InferaDB Matches:**

- ✅ Check (standard across all)
- ✅ BatchCheck (matches OpenFGA/Oso/WorkOS/Cedar, exceeds with streaming)
- ✅ Write (standard across all)
- ✅ Expand (matches SpiceDB/OpenFGA)
- ✅ ListResources (matching SpiceDB/OpenFGA/Oso/WorkOS)
- ✅ ListSubjects (matching SpiceDB/OpenFGA/Oso/WorkOS with streaming)
- ✅ ListRelationships (matching SpiceDB/OpenFGA/Oso/WorkOS with improved naming)
- ✅ Watch (matching SpiceDB/OpenFGA with gRPC + REST/SSE streaming)
- ✅ Wildcards (matching SpiceDB/OpenFGA/WorkOS with `type:*` pattern)

**Where InferaDB Falls Behind:**

- ⚠️ **ABAC** - WASM-only vs native conditions (usability gap)

### Priority for Implementation

**Phase 1 (P0 - Months 1-4):**

1. ✅ ~~ListResources - HIGHEST PRIORITY~~ (COMPLETED Phase 1.1)
2. ✅ ~~ListRelationships - Essential for admin UIs~~ (COMPLETED Phase 1.2 with resource/subject naming)
3. ✅ ~~DeleteRelationships with filtering - Unblock user offboarding~~ (COMPLETED Phase 1.3 with streaming API)
4. ✅ ~~BatchCheck - Performance parity~~ (COMPLETED Phase 1.5 with streaming Check API)
5. Native ABAC conditions - Ease of use parity (NEXT PRIORITY)

**Phase 2 (P1 - Months 5-6):**

6. ✅ ~~LookupSubjects - Complete query surface~~ (COMPLETED Phase 2.1 with reverse graph traversal)
7. Watch API - Real-time capabilities (NEXT)

**Phase 3 (P2 - Months 7-9):** 8. Schema management API 9. gRPC reflection 10. BulkImport/Export

**Phase 4 (Multi-Tenancy):** 11. ✅ ~~Account & Vault Management~~ (COMPLETED Phase 4 - 10 new REST endpoints for multi-tenant account/vault CRUD)

---

**Last Updated**: 2025-11-02
**Next Review**: Phase 5 (Initialization & Migration) or Native ABAC implementation

**See Also:**

- [COMPARISON.md](./COMPARISON.md) - Full competitive analysis
- [ROADMAP.md](./ROADMAP.md) - Implementation plan
- [api/openapi.yaml](./api/openapi.yaml) - REST API specification
- [crates/infera-api/proto/infera.proto](./crates/infera-api/proto/infera.proto) - gRPC specification
