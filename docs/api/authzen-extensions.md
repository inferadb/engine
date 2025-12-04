# InferaDB AuthZEN Extensions

## Overview

InferaDB extends the AuthZEN specification with four custom extensions that provide Relationship-Based Access Control (ReBAC) capabilities beyond the standard authorization evaluation model. These extensions are advertised via the `extensions` object in the `/.well-known/authzen-configuration` metadata discovery endpoint.

```json
{
  "issuer": "https://inferadb.example.com",
  "access_evaluation_endpoint": "https://inferadb.example.com/access/v1/evaluation",
  "extensions": {
    "inferadb_relationship_management": true,
    "inferadb_relation_expansion": true,
    "inferadb_simulation": true,
    "inferadb_realtime_streaming": true
  }
}
```

## Extension Summary

| Extension                          | Purpose                                                 | Key Endpoints                                 |
| ---------------------------------- | ------------------------------------------------------- | --------------------------------------------- |
| `inferadb_relationship_management` | Create, query, and delete relationships                 | `/v1/relationships:write`, `:list`, `:delete` |
| `inferadb_relation_expansion`      | Expand relation trees to visualize authorization graphs | `/v1/expand`                                  |
| `inferadb_simulation`              | Simulate authorization changes before committing        | `/v1/simulate`                                |
| `inferadb_realtime_streaming`      | Watch for relationship changes in real-time             | `/v1/watch`                                   |

## When to Use Extensions vs Core AuthZEN

### Use Core AuthZEN Endpoints When

- **Portability is critical**: You need to integrate with any AuthZEN-compliant system
- **Simple authorization checks**: You only need to answer "can subject perform action on resource?"
- **Batch evaluations**: You need to check multiple permissions at once
- **Search operations**: You need to find authorized resources or subjects
- **Standardized integration**: You're building a generic authorization layer

### Use InferaDB Extensions When

- **Relationship management**: You need to create, modify, or delete the underlying authorization graph
- **Debugging authorization**: You need to understand why a decision was made
- **Authorization visualization**: You need to see the complete relationship tree
- **Testing authorization changes**: You want to simulate changes before applying them
- **Real-time updates**: You need to react to authorization changes immediately
- **Advanced tracing**: You need detailed evaluation traces with timing information

## Extension: `inferadb_relationship_management`

### Purpose

Provides full CRUD operations for the relationship graph that powers InferaDB's authorization decisions. While AuthZEN focuses on read-only evaluation, this extension allows you to modify the authorization state.

### Endpoints

#### `POST /v1/relationships:write`

Create new relationships in the authorization graph.

**Request:**

```json
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
      "resource": "doc:design-doc"
    }
  ]
}
```

**Response:**

```json
{
  "success": true,
  "relationships_created": 2
}
```

**Use Cases:**

- User joins a team
- Document is shared with a group
- Role assignments
- Organizational hierarchy updates

#### `POST /v1/relationships:list`

Query existing relationships with flexible filtering.

**Request:**

```json
{
  "filter": {
    "subject": "user:alice",
    "relation": "member"
  },
  "limit": 100
}
```

**Response:**

```json
{
  "relationships": [
    {
      "subject": "user:alice",
      "relation": "member",
      "resource": "team:engineering"
    },
    {
      "subject": "user:alice",
      "relation": "member",
      "resource": "team:platform"
    }
  ],
  "continuation_token": null
}
```

**Use Cases:**

- List all teams a user belongs to
- Find all members of a resource
- Audit relationship data
- Export authorization state

#### `POST /v1/relationships:delete`

Remove relationships from the authorization graph.

**Request:**

```json
{
  "relationships": [
    {
      "subject": "user:alice",
      "relation": "member",
      "resource": "team:engineering"
    }
  ]
}
```

**Response:**

```json
{
  "success": true,
  "relationships_deleted": 1
}
```

**Use Cases:**

- User leaves a team
- Revoke access to a resource
- Remove expired permissions
- Clean up stale relationships

### Migration from Core AuthZEN

Core AuthZEN assumes relationships exist but doesn't provide APIs to manage them. If you're using:

- **External data source**: Continue using your existing system and only use AuthZEN for evaluation
- **InferaDB as source of truth**: Use this extension to manage relationships directly

## Extension: `inferadb_relation_expansion`

### Purpose

Expands relation trees to show all subjects that have a specific relation to a resource, or all resources that a subject has a relation to. This is critical for debugging authorization decisions and understanding the authorization graph structure.

### Endpoint

#### `POST /v1/expand`

Expand a relation tree from a starting point.

**Request (Expand who can view a document):**

```json
{
  "resource": "doc:design-doc",
  "relation": "viewer",
  "max_depth": 5
}
```

**Response:**

```json
{
  "tree": {
    "resource": "doc:design-doc",
    "relation": "viewer",
    "subjects": [
      {
        "type": "direct",
        "subject": "user:alice"
      },
      {
        "type": "computed",
        "subject": "team:engineering#member",
        "children": [
          {
            "type": "direct",
            "subject": "user:bob"
          },
          {
            "type": "direct",
            "subject": "user:charlie"
          }
        ]
      }
    ]
  }
}
```

**Use Cases:**

- Debug "why does this user have access?"
- Visualize authorization graph
- Generate access control lists
- Audit who has access to sensitive resources
- Understand computed permissions from groups

### Comparison to AuthZEN Search

| Feature            | AuthZEN Search                  | InferaDB Expansion                   |
| ------------------ | ------------------------------- | ------------------------------------ |
| Output             | Flat list of subjects/resources | Hierarchical tree showing derivation |
| Computed relations | Included in results             | Shows how they're computed           |
| Debugging          | Limited insight                 | Full authorization path              |
| Performance        | Optimized for large result sets | Optimized for understanding          |

**When to use which:**

- **AuthZEN Search** (`/access/v1/search/resource`): "Give me all documents user:alice can view" (production queries)
- **InferaDB Expansion** (`/v1/expand`): "Show me why user:alice can view doc:X" (debugging, auditing)

## Extension: `inferadb_simulation`

### Purpose

Simulate authorization decisions with hypothetical relationship changes without persisting them. Essential for testing authorization logic, previewing access changes, and implementing "what-if" scenarios.

### Endpoint

#### `POST /v1/simulate`

Evaluate a check with simulated relationship changes.

**Request (Simulate adding user to team):**

```json
{
  "evaluation": {
    "subject": "user:alice",
    "relation": "viewer",
    "resource": "doc:design-doc"
  },
  "simulated_relationships": {
    "add": [
      {
        "subject": "user:alice",
        "relation": "member",
        "resource": "team:engineering"
      }
    ],
    "remove": []
  }
}
```

**Response:**

```json
{
  "decision": true,
  "trace": {
    "steps": [
      {
        "rule": "team:engineering#member -> viewer @ doc:design-doc",
        "result": "matched",
        "simulated": true
      }
    ]
  }
}
```

**Use Cases:**

- Preview access changes before applying them
- Test authorization schema changes
- Implement "Request Access" workflows with preview
- Validate authorization policies
- Generate access change impact reports

### No AuthZEN Equivalent

AuthZEN does not provide simulation capabilities. This is a unique InferaDB feature for advanced authorization management.

## Extension: `inferadb_realtime_streaming`

### Purpose

Subscribe to real-time notifications when relationships change. Essential for cache invalidation, live UI updates, and reactive authorization systems.

### Endpoint

#### `POST /v1/watch`

Watch for changes to relationships matching a filter.

**Request:**

```json
{
  "filter": {
    "resource": "doc:design-doc"
  }
}
```

**Response (Server-Sent Events stream):**

```text
event: relationship_created
data: {"subject":"user:alice","relation":"viewer","resource":"doc:design-doc","timestamp":"2025-01-15T10:30:00Z"}

event: relationship_deleted
data: {"subject":"user:bob","relation":"editor","resource":"doc:design-doc","timestamp":"2025-01-15T10:31:00Z"}
```

**Use Cases:**

- Invalidate authorization caches when relationships change
- Update UI in real-time when access is granted/revoked
- Trigger workflows on permission changes
- Audit log streaming
- Real-time compliance monitoring

### Comparison to Polling

| Approach                         | Latency            | Server Load             | Network Efficiency       |
| -------------------------------- | ------------------ | ----------------------- | ------------------------ |
| Polling `/v1/relationships:list` | Seconds to minutes | High (frequent queries) | Low (redundant requests) |
| Watch stream `/v1/watch`         | Milliseconds       | Low (single connection) | High (push on change)    |

**When to use:**

- **Watch**: Real-time applications, cache invalidation, live dashboards
- **Polling**: Batch processing, scheduled jobs, offline sync

### No AuthZEN Equivalent

AuthZEN is a synchronous request/response protocol and does not support streaming or pub/sub patterns.

## Extension Discovery and Capability Negotiation

Clients should discover available extensions via the `/.well-known/authzen-configuration` endpoint:

```http
GET /.well-known/authzen-configuration HTTP/1.1
Host: inferadb.example.com
```

```json
{
  "issuer": "https://inferadb.example.com",
  "access_evaluation_endpoint": "https://inferadb.example.com/access/v1/evaluation",
  "access_evaluations_endpoint": "https://inferadb.example.com/access/v1/evaluations",
  "search_resource_endpoint": "https://inferadb.example.com/access/v1/search/resource",
  "search_subject_endpoint": "https://inferadb.example.com/access/v1/search/subject",
  "extensions": {
    "inferadb_relationship_management": true,
    "inferadb_relation_expansion": true,
    "inferadb_simulation": true,
    "inferadb_realtime_streaming": true
  }
}
```

Clients can gracefully degrade functionality if extensions are not available:

```python
config = requests.get("https://inferadb.example.com/.well-known/authzen-configuration").json()

if config.get("extensions", {}).get("inferadb_simulation"):
    # Use simulation for preview
    result = simulate_access_change(user, team)
else:
    # Fall back to direct evaluation
    result = evaluate_access(user, resource)
```

## API Versioning

All InferaDB extension endpoints use the `/v1/` prefix to indicate API version. Core AuthZEN endpoints use `/access/v1/` as specified by the AuthZEN specification.

Future API versions will increment the version number (e.g., `/v2/`, `/access/v2/`).

## Error Handling

Extension endpoints follow the same error handling conventions as core AuthZEN:

- **200 OK**: Successful operation (even for denials or empty results)
- **400 Bad Request**: Invalid request format or parameters
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Authenticated but not authorized for this operation
- **500 Internal Server Error**: Server-side error

Error response format:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Subject field is required",
    "details": {
      "field": "subject",
      "reason": "missing_required_field"
    }
  }
}
```

## Security Considerations

### Relationship Management

- **Write operations**: Must be authenticated and authorized
- **Bulk operations**: May have rate limits to prevent abuse
- **Validation**: Subjects, relations, and resources must conform to schema

### Relation Expansion

- **Depth limits**: Prevent infinite recursion or DoS attacks
- **Result size limits**: Prevent memory exhaustion
- **Authorization**: May require permission to view the expansion

### Simulation

- **Resource limits**: Simulations are isolated and time-limited
- **Side effects**: Simulations MUST NOT persist any changes
- **Audit logging**: Simulations should be logged for security auditing

### Real-time Streaming

- **Connection limits**: Prevent resource exhaustion
- **Authentication**: Must authenticate before establishing watch
- **Filter restrictions**: May restrict filters to prevent broad watches
- **Rate limiting**: May limit event delivery rate

## Implementation Status

| Extension                          | Status         | Endpoints Implemented           |
| ---------------------------------- | -------------- | ------------------------------- |
| `inferadb_relationship_management` | ✅ Implemented | All (`write`, `list`, `delete`) |
| `inferadb_relation_expansion`      | ✅ Implemented | `expand`                        |
| `inferadb_simulation`              | 🚧 Planned     | None                            |
| `inferadb_realtime_streaming`      | 🚧 Planned     | None                            |

See `RELATIONSHIPS.md` for implementation roadmap.

## References

- [AuthZEN Specification](https://openid.github.io/authzen/)
- [InferaDB API Reference](../api/openapi.yaml)
- [AuthZEN Spec Study](./authzen-spec-study.md)
- [RFC 8615 - Well-Known URIs](https://www.rfc-editor.org/rfc/rfc8615.html)

## Examples

### Complete Workflow: Share Document with Team

```python
# 1. Create team membership (relationship_management)
POST /v1/relationships:write
{
  "relationships": [
    {"subject": "user:alice", "relation": "member", "resource": "team:eng"}
  ]
}

# 2. Grant team access to document (relationship_management)
POST /v1/relationships:write
{
  "relationships": [
    {"subject": "team:eng#member", "relation": "viewer", "resource": "doc:123"}
  ]
}

# 3. Verify access with AuthZEN (core)
POST /access/v1/evaluation
{
  "subject": {"type": "user", "id": "alice"},
  "action": {"name": "view"},
  "resource": {"type": "doc", "id": "123"}
}
# Response: {"decision": true}

# 4. Understand why (relation_expansion)
POST /v1/expand
{
  "resource": "doc:123",
  "relation": "viewer"
}
# Response: Shows team:eng#member -> user:alice path

# 5. Watch for changes (realtime_streaming)
POST /v1/watch
{
  "filter": {"resource": "doc:123"}
}
# Stream: Receives events when access changes
```

### Integration Pattern: Authorization Service with Extensions

```typescript
class AuthorizationService {
  async checkAccess(
    subject: string,
    action: string,
    resource: string
  ): Promise<boolean> {
    // Use core AuthZEN for evaluation
    const response = await fetch(
      "https://inferadb.example.com/access/v1/evaluation",
      {
        method: "POST",
        body: JSON.stringify({
          subject: { type: "user", id: subject },
          action: { name: action },
          resource: { type: "document", id: resource },
        }),
      }
    );
    const result = await response.json();
    return result.decision;
  }

  async grantAccess(
    subject: string,
    relation: string,
    resource: string
  ): Promise<void> {
    // Use extension for relationship management
    await fetch("https://inferadb.example.com/v1/relationships:write", {
      method: "POST",
      body: JSON.stringify({
        relationships: [{ subject, relation, resource }],
      }),
    });
  }

  async explainAccess(subject: string, resource: string): Promise<object> {
    // Use extension for debugging
    const response = await fetch("https://inferadb.example.com/v1/expand", {
      method: "POST",
      body: JSON.stringify({ resource, relation: "viewer" }),
    });
    return await response.json();
  }
}
```
