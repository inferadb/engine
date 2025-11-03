# AuthZEN Data Model Mapping

## Overview

This document describes the bidirectional mapping between AuthZEN's standardized data model and InferaDB's native ReBAC (Relationship-Based Access Control) data model. InferaDB supports both formats to maximize compatibility while maintaining its powerful ReBAC capabilities.

## Data Model Comparison

| Concept      | AuthZEN Format                  | InferaDB Format                 | Notes                    |
| ------------ | ------------------------------- | ------------------------------- | ------------------------ |
| Subject      | `{type: "user", id: "alice"}`   | `"user:alice"`                  | Entity performing action |
| Resource     | `{type: "document", id: "123"}` | `"document:123"`                | Entity being accessed    |
| Action       | `{name: "view"}`                | `"viewer"`                      | Operation or relation    |
| Relationship | Implicit                        | `{subject, relation, resource}` | Core primitive           |

## Subject Mapping

### AuthZEN Subject → InferaDB Subject

AuthZEN subjects are structured objects with a `type` and `id`. InferaDB converts these to a compact string format.

**AuthZEN Format:**

```json
{
    "type": "user",
    "id": "alice",
    "properties": {
        "department": "engineering"
    }
}
```

**InferaDB Native Format:**

```
"user:alice"
```

**Conversion Rules:**

- **Parsing**: Extract `type` and `id` from structured object
- **Generation**: Combine as `{type}:{id}`
- **Validation**:
    - Type must match `^[a-z_][a-z0-9_]*$`
    - ID must match `^[a-z0-9_-]+$`
    - Colon `:` is reserved as separator

**Subject Types:**

Common subject types and their mappings:

| AuthZEN Type                           | InferaDB Format       | Description     |
| -------------------------------------- | --------------------- | --------------- |
| `{type: "user", id: "alice"}`          | `user:alice`          | Individual user |
| `{type: "service", id: "api-gateway"}` | `service:api-gateway` | Service account |
| `{type: "group", id: "eng"}`           | `group:eng`           | User group      |
| `{type: "role", id: "admin"}`          | `role:admin`          | Role assignment |

**Subject References (Computed Usersets):**

InferaDB supports referencing all members of a relation on another resource:

**AuthZEN**: Not directly supported
**InferaDB**: `"team:engineering#member"`

This represents "all members of team:engineering" and is used for computed permissions.

## Resource Mapping

### AuthZEN Resource → InferaDB Resource

Resources follow the same structured to string conversion as subjects.

**AuthZEN Format:**

```json
{
    "type": "document",
    "id": "design-proposal",
    "properties": {
        "classification": "internal"
    }
}
```

**InferaDB Native Format:**

```
"document:design-proposal"
```

**Conversion Rules:**

- Same parsing and generation rules as subjects
- Type and ID validation identical to subjects
- Properties are not stored in the type:id format (handled separately in InferaDB)

**Resource Types:**

Common resource types and their mappings:

| AuthZEN Type                          | InferaDB Format      | Description         |
| ------------------------------------- | -------------------- | ------------------- |
| `{type: "document", id: "123"}`       | `document:123`       | Document resource   |
| `{type: "folder", id: "shared"}`      | `folder:shared`      | Folder or directory |
| `{type: "organization", id: "acme"}`  | `organization:acme`  | Top-level org       |
| `{type: "workspace", id: "dev"}`      | `workspace:dev`      | Workspace or tenant |
| `{type: "project", id: "apollo"}`     | `project:apollo`     | Project             |
| `{type: "repository", id: "backend"}` | `repository:backend` | Code repository     |

## Action Mapping

### AuthZEN Action → InferaDB Relation

This is the most complex mapping as AuthZEN actions map to InferaDB relations, but they serve different purposes.

**AuthZEN Action:**

- Represents an operation (e.g., "can_view", "can_edit", "can_delete")
- Used in evaluation requests only
- Not directly stored

**InferaDB Relation:**

- Represents a relationship type (e.g., "viewer", "editor", "owner")
- Stored in the relationship graph
- Can be composed using set operations

**Mapping Strategy:**

InferaDB uses the action name to determine which relation to check. The mapping depends on your schema definition.

**Example Schema Mapping:**

```yaml
# IPL Schema
type document {
  relation viewer: user
  relation editor: user | viewer
  relation owner: user | editor

  permission can_view = viewer
  permission can_edit = editor
  permission can_delete = owner
}
```

**AuthZEN to InferaDB Mapping:**

| AuthZEN Action         | InferaDB Relation | Description       |
| ---------------------- | ----------------- | ----------------- |
| `{name: "can_view"}`   | `viewer`          | Read access       |
| `{name: "can_edit"}`   | `editor`          | Write access      |
| `{name: "can_delete"}` | `owner`           | Delete access     |
| `{name: "can_share"}`  | `owner`           | Share permissions |

**Action Name Conversion:**

InferaDB automatically strips common prefixes and converts action names:

- `can_view` → `viewer` (strip `can_`, add `er`)
- `view` → `viewer` (add `er`)
- `edit` → `editor` (add `or`)
- `admin` → `admin` (unchanged)
- `owner` → `owner` (unchanged)

**Default Mapping Table:**

| Action Name                           | Relation Name |
| ------------------------------------- | ------------- |
| `can_view`, `view`, `read`            | `viewer`      |
| `can_edit`, `edit`, `write`           | `editor`      |
| `can_delete`, `delete`                | `owner`       |
| `can_admin`, `admin`, `administrator` | `admin`       |
| `own`, `owner`                        | `owner`       |
| `manage`, `manager`                   | `manager`     |
| `member`                              | `member`      |

## Format Parsing and Generation

### Type:ID Format Specification

InferaDB's native format uses a colon-separated string: `{type}:{id}`

**Parsing: AuthZEN → InferaDB**

```typescript
function parseAuthZENEntity(entity: AuthZENEntity): string {
    if (typeof entity === "string") {
        // Already in InferaDB format
        return entity;
    }

    // Validate type format
    if (!/^[a-z_][a-z0-9_]*$/.test(entity.type)) {
        throw new Error(`Invalid type format: ${entity.type}`);
    }

    // Validate ID format
    if (!/^[a-z0-9_-]+$/.test(entity.id)) {
        throw new Error(`Invalid id format: ${entity.id}`);
    }

    return `${entity.type}:${entity.id}`;
}
```

**Generation: InferaDB → AuthZEN**

```typescript
function generateAuthZENEntity(nativeFormat: string): AuthZENEntity {
    const [type, id] = nativeFormat.split(":", 2);

    if (!type || !id) {
        throw new Error(`Invalid format: ${nativeFormat}`);
    }

    return {
        type,
        id,
    };
}
```

**Handling Subject References:**

InferaDB's computed userset format includes a `#` separator:

```
"team:engineering#member"
```

This represents "all members of team:engineering". In AuthZEN, this would be represented differently depending on the operation.

**Parsing Subject References:**

```typescript
function parseSubjectReference(ref: string): {
    resource: string;
    relation: string;
} | null {
    if (!ref.includes("#")) {
        return null; // Not a subject reference
    }

    const [resource, relation] = ref.split("#", 2);
    return { resource, relation };
}
```

**Example:**

- InferaDB: `"team:engineering#member"`
- Parsed: `{resource: "team:engineering", relation: "member"}`

## Backward Compatibility

InferaDB maintains backward compatibility by accepting both AuthZEN structured format and native string format in all endpoints.

### Compatibility Rules

1. **Input Acceptance:**
    - All endpoints accept BOTH AuthZEN objects AND InferaDB strings
    - Automatic detection and conversion
    - No breaking changes for existing clients

2. **Output Format:**
    - Core AuthZEN endpoints (`/access/v1/*`) return AuthZEN format
    - Extension endpoints (`/v1/*`) return InferaDB native format
    - Can be controlled via `Accept` header or query parameter (future)

3. **Validation:**
    - Both formats undergo the same validation rules
    - Type and ID constraints are identical
    - Invalid formats rejected with clear error messages

### Migration Path

**Phase 1: Dual Support (Current)**

- All endpoints accept both formats
- Native clients use InferaDB format
- AuthZEN clients use structured format
- No changes required for existing code

**Phase 2: Recommended Format (Future)**

- Documentation recommends AuthZEN format for new integrations
- SDKs default to AuthZEN format
- InferaDB format remains fully supported

**Phase 3: Deprecation (If needed)**

- Clear deprecation timeline (minimum 12 months)
- Migration tools provided
- Both formats continue to work during transition

### Handling Legacy Data

Existing data in InferaDB's native format is automatically compatible:

```rust
// Existing relationship in database
{
  subject: "user:alice",
  relation: "viewer",
  resource: "document:123"
}

// Accessible via AuthZEN endpoint
POST /access/v1/evaluation
{
  "subject": {"type": "user", "id": "alice"},
  "action": {"name": "can_view"},
  "resource": {"type": "document", "id": "123"}
}
// Returns: {"decision": true}
```

No data migration required.

## Endpoint Format Support

Different endpoints support different format combinations based on their purpose.

### Core AuthZEN Endpoints (`/access/v1/*`)

| Endpoint                     | Input Format                        | Output Format   |
| ---------------------------- | ----------------------------------- | --------------- |
| `/access/v1/evaluation`      | AuthZEN objects or InferaDB strings | AuthZEN objects |
| `/access/v1/evaluations`     | AuthZEN objects or InferaDB strings | AuthZEN objects |
| `/access/v1/search/resource` | AuthZEN objects or InferaDB strings | AuthZEN objects |
| `/access/v1/search/subject`  | AuthZEN objects or InferaDB strings | AuthZEN objects |

**Example:**

```http
POST /access/v1/evaluation
Content-Type: application/json

{
  "subject": {"type": "user", "id": "alice"},
  "action": {"name": "view"},
  "resource": {"type": "document", "id": "123"}
}
```

**Alternative (InferaDB format also accepted):**

```http
POST /access/v1/evaluation
Content-Type: application/json

{
  "subject": "user:alice",
  "action": {"name": "view"},
  "resource": "document:123"
}
```

### InferaDB Extension Endpoints (`/v1/*`)

| Endpoint                   | Input Format                        | Output Format          |
| -------------------------- | ----------------------------------- | ---------------------- |
| `/v1/evaluate`             | InferaDB strings or AuthZEN objects | InferaDB strings       |
| `/v1/expand`               | InferaDB strings or AuthZEN objects | InferaDB strings       |
| `/v1/relationships:write`  | InferaDB strings or AuthZEN objects | InferaDB strings       |
| `/v1/relationships:list`   | InferaDB strings or AuthZEN objects | InferaDB strings       |
| `/v1/relationships:delete` | InferaDB strings or AuthZEN objects | InferaDB strings       |
| `/v1/watch`                | InferaDB strings or AuthZEN objects | InferaDB strings (SSE) |

**Example:**

```http
POST /v1/relationships:write
Content-Type: application/json

{
  "relationships": [
    {
      "subject": "user:alice",
      "relation": "viewer",
      "resource": "document:123"
    }
  ]
}
```

**Alternative (AuthZEN format also accepted):**

```http
POST /v1/relationships:write
Content-Type: application/json

{
  "relationships": [
    {
      "subject": {"type": "user", "id": "alice"},
      "relation": "viewer",
      "resource": {"type": "document", "id": "123"}
    }
  ]
}
```

## Conversion Examples

### Example 1: User Viewing Document

**AuthZEN Request:**

```json
{
    "subject": {
        "type": "user",
        "id": "alice"
    },
    "action": {
        "name": "view"
    },
    "resource": {
        "type": "document",
        "id": "quarterly-report"
    }
}
```

**InferaDB Internal Representation:**

```rust
Check {
  subject: "user:alice",
  relation: "viewer",
  resource: "document:quarterly-report"
}
```

**Required Relationship:**

```json
{
    "subject": "user:alice",
    "relation": "viewer",
    "resource": "document:quarterly-report"
}
```

### Example 2: Team Member Access

**Scenario**: User alice is a member of team:engineering, and team:engineering has viewer access to a document.

**Relationships:**

```json
[
    {
        "subject": "user:alice",
        "relation": "member",
        "resource": "team:engineering"
    },
    {
        "subject": "team:engineering#member",
        "relation": "viewer",
        "resource": "document:design-doc"
    }
]
```

**AuthZEN Request:**

```json
{
    "subject": { "type": "user", "id": "alice" },
    "action": { "name": "view" },
    "resource": { "type": "document", "id": "design-doc" }
}
```

**InferaDB Evaluation Path:**

1. Check if `user:alice` has `viewer` relation to `document:design-doc`
2. Expand `team:engineering#member` → includes `user:alice`
3. `user:alice` ∈ `team:engineering#member`
4. `team:engineering#member` has `viewer` → `user:alice` has `viewer`
5. Return `{"decision": true}`

### Example 3: Batch Evaluation

**AuthZEN Batch Request:**

```json
{
    "evaluations": [
        {
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "view" },
            "resource": { "type": "document", "id": "doc1" }
        },
        {
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "edit" },
            "resource": { "type": "document", "id": "doc1" }
        },
        {
            "subject": { "type": "user", "id": "alice" },
            "action": { "name": "view" },
            "resource": { "type": "document", "id": "doc2" }
        }
    ]
}
```

**InferaDB Batch Checks:**

```rust
[
  Check { subject: "user:alice", relation: "viewer", resource: "document:doc1" },
  Check { subject: "user:alice", relation: "editor", resource: "document:doc1" },
  Check { subject: "user:alice", relation: "viewer", resource: "document:doc2" },
]
```

**AuthZEN Response:**

```json
{
    "evaluations": [
        { "decision": true },
        { "decision": false },
        { "decision": true }
    ]
}
```

### Example 4: Resource Search

**AuthZEN Request:**

```json
{
    "subject": { "type": "user", "id": "alice" },
    "action": { "name": "view" },
    "resource_type": "document"
}
```

**InferaDB Query:**

```rust
ListResources {
  subject: "user:alice",
  relation: "viewer",
  resource_type: "document"
}
```

**InferaDB Native Response:**

```json
{
    "resources": ["document:doc1", "document:doc2", "document:doc3"]
}
```

**AuthZEN Response:**

```json
{
    "resources": [
        { "type": "document", "id": "doc1" },
        { "type": "document", "id": "doc2" },
        { "type": "document", "id": "doc3" }
    ]
}
```

### Example 5: Subject Search

**AuthZEN Request:**

```json
{
    "resource": { "type": "document", "id": "design-doc" },
    "action": { "name": "edit" }
}
```

**InferaDB Query:**

```rust
ListSubjects {
  resource: "document:design-doc",
  relation: "editor"
}
```

**InferaDB Native Response:**

```json
{
    "subjects": ["user:alice", "user:bob", "team:engineering#member"]
}
```

**AuthZEN Response:**

```json
{
    "subjects": [
        { "type": "user", "id": "alice" },
        { "type": "user", "id": "bob" },
        { "type": "team", "id": "engineering", "relation": "member" }
    ]
}
```

Note: Subject references (`team:engineering#member`) are converted to include the relation field.

### Example 6: Creating Relationships

**InferaDB Extension Request:**

```json
POST /v1/relationships:write
{
  "relationships": [
    {
      "subject": "user:alice",
      "relation": "member",
      "resource": "team:engineering"
    },
    {
      "subject": "team:engineering#member",
      "relation": "viewer",
      "resource": "folder:shared"
    }
  ]
}
```

**Equivalent using AuthZEN format:**

```json
POST /v1/relationships:write
{
  "relationships": [
    {
      "subject": {"type": "user", "id": "alice"},
      "relation": "member",
      "resource": {"type": "team", "id": "engineering"}
    },
    {
      "subject": {
        "type": "team",
        "id": "engineering",
        "relation": "member"
      },
      "relation": "viewer",
      "resource": {"type": "folder", "id": "shared"}
    }
  ]
}
```

## Implementation Notes

### String Parsing Performance

InferaDB optimizes for the native string format internally:

- **Storage**: All relationships stored as `type:id` strings
- **Indexes**: Optimized for string-based lookups
- **Conversion Overhead**: Minimal (single string split or concat)
- **Memory**: String format more compact than structured objects

### Validation Order

1. **Format Detection**: Determine if input is string or object
2. **Structure Validation**: Verify required fields present
3. **Content Validation**: Check type and ID patterns
4. **Conversion**: Transform to internal format if needed
5. **Processing**: Execute the operation

### Error Handling

**Invalid Type Format:**

```json
{
    "error": {
        "code": "invalid_type_format",
        "message": "Type must match pattern ^[a-z_][a-z0-9_]*$",
        "details": {
            "field": "subject.type",
            "value": "User",
            "expected": "user"
        }
    }
}
```

**Invalid ID Format:**

```json
{
    "error": {
        "code": "invalid_id_format",
        "message": "ID must match pattern ^[a-z0-9_-]+$",
        "details": {
            "field": "resource.id",
            "value": "Doc@123",
            "expected": "doc-123"
        }
    }
}
```

**Missing Required Field:**

```json
{
    "error": {
        "code": "missing_required_field",
        "message": "Subject must have both 'type' and 'id' fields",
        "details": {
            "field": "subject",
            "missing": ["id"]
        }
    }
}
```

## Best Practices

### 1. Use Consistent Format Within Application

Choose either AuthZEN or InferaDB format and use consistently throughout your application to reduce conversion overhead and improve code readability.

### 2. Validate Before Sending

Validate type and ID formats client-side before making API requests to get faster feedback and reduce round trips.

### 3. Cache Format Conversions

If you need to convert between formats frequently, cache the results to avoid repeated string operations.

### 4. Leverage Type Safety

Use TypeScript or other type-safe languages with proper type definitions for AuthZEN entities:

```typescript
interface AuthZENEntity {
    type: string;
    id: string;
    properties?: Record<string, any>;
}

interface AuthZENEvaluationRequest {
    subject: AuthZENEntity | string;
    action: { name: string };
    resource: AuthZENEntity | string;
}
```

### 5. Handle Subject References Explicitly

When working with computed usersets (subject references), explicitly handle the `#` separator:

```typescript
function isSubjectReference(subject: string): boolean {
    return subject.includes("#");
}

function parseSubjectRef(ref: string): {
    type: string;
    id: string;
    relation: string;
} {
    const [typeId, relation] = ref.split("#");
    const [type, id] = typeId.split(":");
    return { type, id, relation };
}
```

## Migration Guide

### Migrating from Native Format to AuthZEN

**Before:**

```javascript
const response = await fetch("/v1/evaluate", {
    method: "POST",
    body: JSON.stringify({
        subject: "user:alice",
        relation: "viewer",
        resource: "document:123",
    }),
});
```

**After:**

```javascript
const response = await fetch("/access/v1/evaluation", {
    method: "POST",
    body: JSON.stringify({
        subject: { type: "user", id: "alice" },
        action: { name: "view" },
        resource: { type: "document", id: "123" },
    }),
});
```

### Migrating from AuthZEN to Native Format

**Before:**

```javascript
const response = await fetch("/access/v1/evaluation", {
    method: "POST",
    body: JSON.stringify({
        subject: { type: "user", id: "alice" },
        action: { name: "view" },
        resource: { type: "document", id: "123" },
    }),
});
```

**After:**

```javascript
const response = await fetch("/v1/evaluate", {
    method: "POST",
    body: JSON.stringify({
        subject: "user:alice",
        relation: "viewer",
        resource: "document:123",
    }),
});
```

## See Also

- [AuthZEN Specification](https://openid.github.io/authzen/)
- [AuthZEN Extensions](./authzen-extensions.md)
- [AuthZEN Spec Study](./authzen-spec-study.md)
- [InferaDB API Reference](../api/openapi.yaml)
- [InferaDB IPL Schema Language](../ipl/README.md)
