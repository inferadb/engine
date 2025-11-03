# AuthZEN Specification Study

**Version**: 1.0
**Date**: 2025-11-02
**Purpose**: Comprehensive study of the AuthZEN specification for InferaDB implementation

---

## Executive Summary

AuthZEN (Authorization API) is an OpenID Foundation standard that defines a common interface for authorization decision-making. This document analyzes the specification to guide InferaDB's implementation of AuthZEN-compliant endpoints.

**Key Findings**:

- AuthZEN uses versioned paths: `/access/v1/`
- All operations use POST method with JSON payloads
- Standard data model: Subject + Resource + Action → Decision
- Extensible through properties, context, and registered capabilities
- InferaDB's ReBAC features extend beyond AuthZEN's core scope

---

## 1. Required Features

The AuthZEN specification mandates the following capabilities for compliant implementations:

### 1.1 Access Evaluation API (Single)

**Endpoint**: `POST /access/v1/evaluation`

**Purpose**: Determine if a specific access request is permitted

**Required Fields**:

- `subject` (object, required): Principal making the request
- `resource` (object, required): Target entity
- `action` (object, required): Intended operation
- `context` (object, optional): Environmental attributes

**Response**:

- HTTP 200 with `{"decision": boolean, "context": object}`
- Decision `false` does NOT return error status; it returns 200 with decision=false

**Compliance**: ✅ REQUIRED for all implementations

### 1.2 HTTPS JSON Binding

**Content Type**: `application/json` (required)

**Transport**: HTTPS (required for production)

**Method**: POST (required for all operations)

**Compliance**: ✅ REQUIRED for all implementations

---

## 2. Optional Features

AuthZEN defines several optional features that implementations MAY provide:

### 2.1 Batch Evaluations API

**Endpoint**: `POST /access/v1/evaluations`

**Purpose**: Process multiple authorization evaluations in a single request (boxcarring)

**Request Format**:

```json
{
  "evaluations": [
    {
      "subject": {...},
      "resource": {...},
      "action": {...},
      "context": {...}
    },
    ...
  ],
  "options": "string (optional)"
}
```

**Options**:

- `execute_all`: Evaluate all requests regardless of individual results
- `deny_on_first_deny`: Stop on first denial
- `permit_on_first_permit`: Stop on first permit

**Response**:

```json
{
  "evaluations": [
    {
      "decision": boolean,
      "context": object
    },
    ...
  ]
}
```

**Compliance**: ⚠️ OPTIONAL (strongly recommended for performance)

### 2.2 Search APIs

AuthZEN defines three search endpoints:

#### 2.2.1 Subject Search

**Endpoint**: `POST /access/v1/search/subject`

**Purpose**: Discover which subjects can perform an action on a resource

**Request**:

```json
{
    "resource": {
        "type": "string",
        "id": "string"
    },
    "action": {
        "name": "string"
    },
    "subject_type": "string (optional)",
    "page": {
        "size": "integer (optional)",
        "token": "string (optional)"
    }
}
```

**Response**:

```json
{
    "subjects": [
        {
            "type": "string",
            "id": "string",
            "properties": {}
        }
    ],
    "page": {
        "next_token": "string (optional)"
    }
}
```

**Compliance**: ⚠️ OPTIONAL

#### 2.2.2 Resource Search

**Endpoint**: `POST /access/v1/search/resource`

**Purpose**: Discover which resources a subject can access with a specific action

**Request**:

```json
{
    "subject": {
        "type": "string",
        "id": "string"
    },
    "action": {
        "name": "string"
    },
    "resource_type": "string (optional)",
    "page": {
        "size": "integer (optional)",
        "token": "string (optional)"
    }
}
```

**Response**:

```json
{
    "resources": [
        {
            "type": "string",
            "id": "string",
            "properties": {}
        }
    ],
    "page": {
        "next_token": "string (optional)"
    }
}
```

**Compliance**: ⚠️ OPTIONAL

#### 2.2.3 Action Search

**Endpoint**: `POST /access/v1/search/action`

**Purpose**: Discover which actions a subject can perform on a resource

**Request**:

```json
{
    "subject": {
        "type": "string",
        "id": "string"
    },
    "resource": {
        "type": "string",
        "id": "string"
    },
    "page": {
        "size": "integer (optional)",
        "token": "string (optional)"
    }
}
```

**Response**:

```json
{
    "actions": [
        {
            "name": "string",
            "properties": {}
        }
    ],
    "page": {
        "next_token": "string (optional)"
    }
}
```

**Compliance**: ⚠️ OPTIONAL

### 2.3 Well-Known Metadata Endpoint

**Endpoint**: `GET /.well-known/authzen-configuration`

**Purpose**: Metadata and capability discovery per RFC 8615

**Response**:

```json
{
    "issuer": "string (REQUIRED)",
    "access_evaluation_endpoint": "string (optional)",
    "access_evaluations_endpoint": "string (optional)",
    "search_subject_endpoint": "string (optional)",
    "search_resource_endpoint": "string (optional)",
    "search_action_endpoint": "string (optional)",
    "capabilities": ["string (URN format)"],
    "signed_metadata": "string (JWT, optional)"
}
```

**Placement**: Between host and path per RFC 8615

- ✅ Correct: `https://pdp.example.com/.well-known/authzen-configuration`
- ❌ Incorrect: `https://pdp.example.com/api/.well-known/authzen-configuration`

**Compliance**: ⚠️ OPTIONAL (strongly recommended for discovery)

### 2.4 Pagination Support

**Mechanism**: Opaque token-based pagination

**Request**:

```json
{
    "page": {
        "size": 100,
        "token": "opaque_cursor_string",
        "properties": {}
    }
}
```

**Response**:

```json
{
    "page": {
        "next_token": "next_cursor_string",
        "prev_token": "prev_cursor_string",
        "properties": {}
    }
}
```

**Notes**:

- Tokens are opaque and implementation-specific
- `page.properties` allows custom pagination parameters
- Size limits are implementation-defined

**Compliance**: ⚠️ OPTIONAL

---

## 3. Error Response Format

AuthZEN uses standard HTTP status codes with JSON error bodies:

### 3.1 HTTP Status Codes

| Status Code                   | Meaning                   | Use Case                                       |
| ----------------------------- | ------------------------- | ---------------------------------------------- |
| **200 OK**                    | Success                   | Successful evaluation (even if decision=false) |
| **400 Bad Request**           | Malformed request         | Invalid JSON, missing required fields          |
| **401 Unauthorized**          | Authentication failure    | Missing or invalid credentials                 |
| **403 Forbidden**             | Access denied to endpoint | Authenticated but insufficient permissions     |
| **500 Internal Server Error** | Server processing error   | PDP internal failure                           |

### 3.2 Important Distinction

⚠️ **Authorization Denial vs Request Error**:

- Authorization denial (decision=false): Returns **200 OK** with `{"decision": false}`
- Request error (malformed): Returns **400 Bad Request** with error message

This is a critical distinction. A successful evaluation that denies access is NOT an error.

### 3.3 Error Response Body

Error responses include a descriptive message:

```json
{
    "error": "string",
    "error_description": "string (optional)"
}
```

**Note**: The specification does not mandate a specific error body schema, but recommends descriptive messages.

---

## 4. Request/Response Content Types

### 4.1 Content Type Header

**Required**: `Content-Type: application/json`

**For Requests**: All POST requests MUST use `application/json`

**For Responses**: All responses MUST use `application/json`

### 4.2 Character Encoding

**Default**: UTF-8

**Recommendation**: Explicitly set `Content-Type: application/json; charset=utf-8`

### 4.3 Accept Header

**Client Requests**: Should include `Accept: application/json`

**PDP Behavior**: If client sends incompatible Accept header, PDP SHOULD return 406 Not Acceptable (though not explicitly required by spec)

---

## 5. Data Model

### 5.1 Subject Structure

**Purpose**: Represents the principal (user, service, group) making the request

**Schema**:

```json
{
    "type": "string (REQUIRED)",
    "id": "string (REQUIRED)",
    "properties": {
        "key": "value (OPTIONAL)"
    }
}
```

**Examples**:

```json
{
  "type": "user",
  "id": "alice"
}

{
  "type": "service",
  "id": "payment-service",
  "properties": {
    "environment": "production"
  }
}
```

### 5.2 Resource Structure

**Purpose**: Represents the target entity being accessed

**Schema**:

```json
{
    "type": "string (REQUIRED)",
    "id": "string (REQUIRED)",
    "properties": {
        "key": "value (OPTIONAL)"
    }
}
```

**Examples**:

```json
{
  "type": "document",
  "id": "readme.md"
}

{
  "type": "api",
  "id": "/v1/users",
  "properties": {
    "method": "POST"
  }
}
```

### 5.3 Action Structure

**Purpose**: Represents the operation being performed

**Schema**:

```json
{
    "name": "string (REQUIRED)",
    "properties": {
        "key": "value (OPTIONAL)"
    }
}
```

**Examples**:

```json
{
  "name": "read"
}

{
  "name": "execute",
  "properties": {
    "mode": "privileged"
  }
}
```

### 5.4 Context Object

**Purpose**: Environmental attributes for the request

**Schema**: Flexible object with arbitrary key-value pairs

**Examples**:

```json
{
    "time": "2025-11-02T10:00:00Z",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0..."
}
```

### 5.5 Decision Response

**Purpose**: Authorization decision result

**Schema**:

```json
{
    "decision": "boolean (REQUIRED)",
    "context": {
        "id": "string (optional)",
        "reason_admin": {
            "en": "string (optional)"
        },
        "reason_user": {
            "en": "string (optional)"
        }
    }
}
```

**Fields**:

- `decision`: `true` (permit) or `false` (deny)
- `context.id`: Unique evaluation identifier
- `context.reason_admin`: Admin-facing explanation (localized)
- `context.reason_user`: User-facing explanation (localized)
- `context` may include custom fields for obligations, advice, etc.

---

## 6. Extension Mechanisms

AuthZEN provides multiple extension points for implementation-specific features:

### 6.1 Properties Objects

**Location**: Subject, Resource, and Action objects

**Purpose**: Arbitrary key-value attributes

**Use Cases**:

- Subject properties: roles, groups, department
- Resource properties: owner, classification, tags
- Action properties: method, protocol, parameters

**Example**:

```json
{
    "subject": {
        "type": "user",
        "id": "alice",
        "properties": {
            "department": "engineering",
            "clearance_level": 3
        }
    }
}
```

### 6.2 Context Objects

**Location**: Request and response

**Purpose**: Environmental and implementation-specific data

**Request Context Use Cases**:

- IP address, geolocation
- Time of day, date
- Client metadata

**Response Context Use Cases**:

- Evaluation ID for auditing
- Reasons for decision (admin/user-facing)
- Obligations (e.g., "must audit this access")
- Step-up authentication requirements

### 6.3 Decision Context

**Location**: Evaluation response

**Purpose**: Implementation-specific guidance

**Common Uses**:

- `reason_admin`: Detailed explanation for admins
- `reason_user`: User-friendly explanation
- `obligations`: Actions that must be taken if decision is permit
- `advice`: Optional recommendations
- `step_up_required`: Additional authentication needed

**Example**:

```json
{
    "decision": true,
    "context": {
        "id": "eval_abc123",
        "reason_admin": {
            "en": "User alice has view permission via group membership"
        },
        "obligations": [{ "type": "audit", "level": "high" }]
    }
}
```

### 6.4 IANA Capability Registry

**Purpose**: Register new capabilities via URN

**Format**: `urn:ietf:params:authzen:capability:capability-name`

**Discovery**: Via `.well-known/authzen-configuration` capabilities array

**Example**:

```json
{
    "capabilities": [
        "urn:ietf:params:authzen:capability:relationship-management",
        "urn:ietf:params:authzen:capability:relation-expansion"
    ]
}
```

### 6.5 Pagination Properties

**Location**: `page.properties` object

**Purpose**: Implementation-specific pagination parameters

**Use Cases**:

- Custom sorting: `{"sort_by": "name", "order": "asc"}`
- Filtering: `{"filter": "active_only"}`
- Performance hints: `{"consistency": "eventual"}`

### 6.6 Batch Evaluation Options

**Location**: `options` field in batch evaluations request

**Defined Options**:

- `execute_all`
- `deny_on_first_deny`
- `permit_on_first_permit`

**Extensibility**: New options can be defined in registered specifications

### 6.7 Signed Metadata

**Location**: `.well-known/authzen-configuration` response

**Purpose**: Cryptographically validated metadata

**Format**: JWT (JSON Web Token)

**Field**: `signed_metadata`

**Use Case**: Ensure metadata integrity and authenticity

---

## 7. InferaDB Features Not in AuthZEN

The following InferaDB capabilities extend beyond the AuthZEN specification:

### 7.1 Relationship Management (CRUD)

**Endpoints**:

- `POST /v1/relationships:write` - Create relationships
- `POST /v1/relationships:list` - Query relationships
- `POST /v1/relationships:delete` - Delete relationships
- `GET /v1/relationships/{resource}/{relation}/{subject}` - Exact match query
- `DELETE /v1/relationships/{resource}/{relation}/{subject}` - Exact match deletion

**Purpose**: Direct ReBAC relationship management

**AuthZEN Status**: ❌ Not defined in AuthZEN spec

**Justification**: AuthZEN focuses on authorization decisions, not relationship data management. This is an InferaDB extension for ReBAC systems.

### 7.2 Relation Tree Expansion

**Endpoint**: `POST /v1/expand`

**Purpose**: Expand complete relation tree for debugging/visualization

**Request**:

```json
{
    "resource": "document:readme",
    "relation": "viewer"
}
```

**Response**: Tree structure showing all subjects and derived permissions

**AuthZEN Status**: ❌ Not defined in AuthZEN spec

**Justification**: Debugging and visualization tool specific to ReBAC systems.

### 7.3 Simulation with Ephemeral Relationships

**Endpoint**: `POST /v1/simulate`

**Purpose**: Test authorization with temporary relationships (not persisted)

**Request**:

```json
{
  "subject": {...},
  "resource": {...},
  "action": {...},
  "ephemeral_relationships": [
    {"resource": "...", "relation": "...", "subject": "..."}
  ]
}
```

**AuthZEN Status**: ❌ Not defined in AuthZEN spec

**Justification**: Testing and "what-if" analysis tool. Could potentially use AuthZEN's context mechanism but goes beyond typical evaluation.

### 7.4 Real-time Change Streaming

**Endpoint**: `POST /v1/watch`

**Purpose**: Subscribe to relationship change events (SSE/WebSocket)

**Response**: Stream of create/delete events

**AuthZEN Status**: ❌ Not defined in AuthZEN spec

**Justification**: Real-time synchronization for distributed systems. Not part of authorization evaluation flow.

### 7.5 Native Format (type:id strings)

**Format**: `"user:alice"`, `"document:readme"`

**AuthZEN Format**: `{"type": "user", "id": "alice"}`

**InferaDB Approach**: Support both formats

- AuthZEN endpoints: Structured format
- Native endpoints: String format or structured
- Internal storage: String format (more compact)

**AuthZEN Status**: ⚠️ Partial alignment (different serialization)

---

## 8. Feature Comparison Matrix

| Feature                   | AuthZEN Status | InferaDB Support | Implementation Strategy                                  |
| ------------------------- | -------------- | ---------------- | -------------------------------------------------------- |
| **Single Evaluation**     | ✅ Required    | ✅ Supported     | Full AuthZEN compliance via `/access/v1/evaluation`      |
| **Batch Evaluations**     | ⚠️ Optional    | ✅ Supported     | Full AuthZEN compliance via `/access/v1/evaluations`     |
| **Subject Search**        | ⚠️ Optional    | ✅ Supported     | Full AuthZEN compliance via `/access/v1/search/subject`  |
| **Resource Search**       | ⚠️ Optional    | ✅ Supported     | Full AuthZEN compliance via `/access/v1/search/resource` |
| **Action Search**         | ⚠️ Optional    | ❌ Not planned   | Low priority (ReBAC uses relations, not actions)         |
| **Well-Known Metadata**   | ⚠️ Optional    | ✅ Planned       | `/.well-known/authzen-configuration` with extensions     |
| **Pagination**            | ⚠️ Optional    | ✅ Supported     | Token-based pagination in search APIs                    |
| **Relationship CRUD**     | ❌ Not in spec | ✅ Supported     | Extension: `/v1/relationships:*` endpoints               |
| **Relation Expansion**    | ❌ Not in spec | ✅ Supported     | Extension: `/v1/expand` endpoint                         |
| **Simulation**            | ❌ Not in spec | ✅ Supported     | Extension: `/v1/simulate` endpoint                       |
| **Real-time Streaming**   | ❌ Not in spec | ✅ Supported     | Extension: `/v1/watch` endpoint                          |
| **HTTPS/JSON Binding**    | ✅ Required    | ✅ Supported     | Full compliance                                          |
| **Error Response Format** | ✅ Defined     | ✅ Supported     | HTTP status codes + JSON errors                          |
| **Structured Entities**   | ✅ Defined     | ✅ Supported     | Both AuthZEN format and native string format             |

**Legend**:

- ✅ Required/Supported: Full compliance or support
- ⚠️ Optional: Recommended but not required
- ❌ Not in spec/Not planned: Not part of AuthZEN or not implementing

---

## 9. Implementation Recommendations

### 9.1 Compliance Strategy

**Phase 1: Core AuthZEN Compliance**

1. Implement `/access/v1/evaluation` (required)
2. Implement `/access/v1/evaluations` (optional but recommended)
3. Implement `/access/v1/search/resource` (optional but recommended)
4. Implement `/access/v1/search/subject` (optional but recommended)
5. Implement `/.well-known/authzen-configuration` (optional but recommended)

**Phase 2: Extensions**

1. Version native API under `/v1/` prefix
2. Implement relationship CRUD as extensions
3. Implement relation expansion, simulation, watch as extensions
4. Document extensions in well-known metadata

### 9.2 Data Model Adapter

Create bidirectional adapter:

- **AuthZEN → InferaDB**: Parse `{"type": "user", "id": "alice"}` → `"user:alice"`
- **InferaDB → AuthZEN**: Format `"user:alice"` → `{"type": "user", "id": "alice"}`

### 9.3 Extension Declaration

In `/.well-known/authzen-configuration`:

```json
{
    "issuer": "https://inferadb.example.com",
    "access_evaluation_endpoint": "https://inferadb.example.com/access/v1/evaluation",
    "access_evaluations_endpoint": "https://inferadb.example.com/access/v1/evaluations",
    "search_subject_endpoint": "https://inferadb.example.com/access/v1/search/subject",
    "search_resource_endpoint": "https://inferadb.example.com/access/v1/search/resource",
    "capabilities": [
        "urn:ietf:params:authzen:capability:relationship-management",
        "urn:ietf:params:authzen:capability:relation-expansion",
        "urn:ietf:params:authzen:capability:simulation",
        "urn:ietf:params:authzen:capability:realtime-streaming"
    ],
    "extensions": {
        "inferadb_relationship_management": true,
        "inferadb_relation_expansion": true,
        "inferadb_simulation": true,
        "inferadb_realtime_streaming": true,
        "relationship_write_endpoint": "https://inferadb.example.com/v1/relationships:write",
        "relationship_list_endpoint": "https://inferadb.example.com/v1/relationships:list",
        "relationship_delete_endpoint": "https://inferadb.example.com/v1/relationships:delete",
        "expand_endpoint": "https://inferadb.example.com/v1/expand",
        "simulate_endpoint": "https://inferadb.example.com/v1/simulate",
        "watch_endpoint": "https://inferadb.example.com/v1/watch"
    }
}
```

### 9.4 Versioning Strategy

**Chosen Approach**: URL versioning

- AuthZEN endpoints: `/access/v1/*` (per spec)
- Native endpoints: `/v1/*` (InferaDB versioning)
- Future evolution: `/access/v2/*`, `/v2/*` as needed

**Benefits**:

- Clear separation of API versions
- Follows AuthZEN spec exactly
- Allows independent evolution of native API

---

## 10. Key Takeaways

1. **AuthZEN is evaluation-focused**: It defines how to ask "can X do Y on Z?" but not how to manage the underlying policies or relationships.

2. **POST-only design**: All operations use POST, even read-only queries. This is intentional for consistency and to avoid URL length limits.

3. **200 OK for denials**: A decision of `false` is NOT an HTTP error. Only malformed requests or server failures return error codes.

4. **Extensible by design**: Properties, context, capabilities, and pagination mechanisms allow implementation-specific features.

5. **InferaDB extends thoughtfully**: Our ReBAC features go beyond AuthZEN but don't conflict with it. We can be fully AuthZEN-compliant while offering additional capabilities.

6. **Version path structure**: `/access/v1/` is mandated by the spec for AuthZEN endpoints.

7. **Well-known discovery**: `/.well-known/authzen-configuration` is the standard way for clients to discover PDP capabilities.

8. **Opaque pagination**: Token-based pagination is recommended over offset/limit for consistency and performance.

---

## 11. References

- [AuthZEN Specification](https://openid.github.io/authzen/)
- [RFC 8615 - Well-Known URIs](https://www.rfc-editor.org/rfc/rfc8615.html)
- [OpenID Foundation AuthZEN Working Group](https://openid.net/wg/authzen/)
- InferaDB RELATIONSHIPS.md (implementation plan)

---

## Appendix A: Complete Endpoint Catalog

### AuthZEN Core Endpoints (Spec-Defined)

| Method | Path                                 | Purpose                    | Status   |
| ------ | ------------------------------------ | -------------------------- | -------- |
| GET    | `/.well-known/authzen-configuration` | Metadata discovery         | Optional |
| POST   | `/access/v1/evaluation`              | Single authorization check | Required |
| POST   | `/access/v1/evaluations`             | Batch authorization checks | Optional |
| POST   | `/access/v1/search/subject`          | Find authorized subjects   | Optional |
| POST   | `/access/v1/search/resource`         | Find authorized resources  | Optional |
| POST   | `/access/v1/search/action`           | Find authorized actions    | Optional |

### InferaDB Native Endpoints (Extensions)

| Method | Path                              | Purpose                                 | Category          |
| ------ | --------------------------------- | --------------------------------------- | ----------------- |
| POST   | `/v1/evaluate`                    | Evaluation (native format, SSE support) | Evaluation        |
| POST   | `/v1/relationships:write`         | Create relationships                    | Relationship Mgmt |
| POST   | `/v1/relationships:list`          | Query relationships                     | Relationship Mgmt |
| POST   | `/v1/relationships:delete`        | Delete relationships                    | Relationship Mgmt |
| GET    | `/v1/relationships/{r}/{rel}/{s}` | Exact match query                       | Relationship Mgmt |
| DELETE | `/v1/relationships/{r}/{rel}/{s}` | Exact match deletion                    | Relationship Mgmt |
| POST   | `/v1/expand`                      | Expand relation tree                    | ReBAC Tooling     |
| POST   | `/v1/simulate`                    | Simulate with ephemeral data            | ReBAC Tooling     |
| POST   | `/v1/watch`                       | Stream relationship changes             | Real-time         |
| POST   | `/v1/resources:list`              | List accessible resources (native)      | Search            |
| POST   | `/v1/subjects:list`               | List authorized subjects (native)       | Search            |

---

**Document Status**: Complete
**Next Steps**: Proceed to Phase 1.2 (Update OpenAPI Specification)
