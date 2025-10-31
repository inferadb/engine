# REST API Reference

InferaDB provides a RESTful HTTP/JSON API for authorization checks and relationship management.

**🚀 Interactive API Explorer**: Try the API interactively with [Swagger UI](./swagger-ui.html)

**📋 OpenAPI Specification**: View the complete [OpenAPI spec](./openapi.yaml)

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

InferaDB supports JWT (JSON Web Token) authentication with multiple signing algorithms:

- **EdDSA** (Ed25519) - Recommended for new applications
- **RS256** (RSA with SHA-256) - Industry standard
- **ES256** (ECDSA with P-256) - High performance

**Authentication Header**:
```http
Authorization: Bearer YOUR_JWT_TOKEN
```

**Required Scopes**:
- `inferadb.read` - Permission checks, expand, list operations
- `inferadb.write` - Write relationships
- `inferadb.delete` - Delete relationships
- `inferadb.watch` - Watch for change events

See the [Authentication Guide](../docs/security/authentication.md) for detailed setup instructions.

**Note**: Authentication can be disabled for development by setting `auth.enabled: false` in configuration.

## Endpoints

### Health Check

Check if the service is running.

#### Request

```http
GET /health
```

#### Response

```json
{
  "status": "healthy",
  "version": "0.1.0"
}
```

**Status Codes**:

- `200 OK` - Service is healthy

---

### Check Permission

Check if a subject has a specific permission on a resource.

#### Request

```http
POST /check
Content-Type: application/json

{
  "subject": "user:alice",
  "resource": "document:readme",
  "permission": "can_view",
  "context": {
    "ip_address": "192.168.1.1",
    "time": "2024-01-15T10:30:00Z"
  }
}
```

**Parameters**:

- `subject` (string, required): The user or entity requesting access
- `resource` (string, required): The resource being accessed
- `permission` (string, required): The permission being checked
- `context` (object, optional): Additional context for WASM modules

#### Response

```json
{
  "decision": "allow"
}
```

**Fields**:

- `decision` (string): Either `"allow"` or `"deny"`

**Status Codes**:

- `200 OK` - Check completed successfully
- `400 Bad Request` - Invalid request format
- `500 Internal Server Error` - Evaluation error

#### Examples

**Allow Decision**:

```bash
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "can_view"
  }'
```

Response:

```json
{
  "decision": "allow"
}
```

**Deny Decision**:

```bash
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:bob",
    "resource": "document:secret",
    "permission": "can_view"
  }'
```

Response:

```json
{
  "decision": "deny"
}
```

---

### Check with Trace

Check permission and return detailed evaluation trace for debugging.

#### Request

```http
POST /check/trace
Content-Type: application/json

{
  "subject": "user:alice",
  "resource": "document:readme",
  "permission": "can_view"
}
```

**Parameters**: Same as `/check`

#### Response

```json
{
  "decision": "allow",
  "trace": {
    "decision": "allow",
    "node_type": "union",
    "children": [
      {
        "decision": "allow",
        "node_type": "direct",
        "relation": "viewer",
        "children": []
      },
      {
        "decision": "deny",
        "node_type": "computed_userset",
        "relation": "editor",
        "children": []
      }
    ]
  }
}
```

**Trace Node Fields**:

- `decision` (string): Decision at this node
- `node_type` (string): Type of evaluation node
  - `direct` - Direct tuple lookup
  - `computed_userset` - Computed relation
  - `union` - OR operation
  - `intersection` - AND operation
  - `exclusion` - EXCEPT operation
  - `tuple_to_userset` - Indirect relation
- `relation` (string, optional): Relation being evaluated
- `children` (array): Sub-evaluations

**Status Codes**: Same as `/check`

---

### Expand Relation

Expand a relation into a tree showing all users and how they have access.

#### Request

```http
POST /expand
Content-Type: application/json

{
  "resource": "document:readme",
  "relation": "can_view"
}
```

**Parameters**:

- `resource` (string, required): The resource to expand
- `relation` (string, required): The relation to expand

#### Response

```json
{
  "tree": {
    "node_type": "union",
    "children": [
      {
        "node_type": "this",
        "children": []
      },
      {
        "node_type": "computed_userset",
        "relation": "editor",
        "children": [
          {
            "node_type": "this",
            "children": []
          }
        ]
      }
    ]
  }
}
```

**Node Types**:

- `this` - Direct relation
- `computed_userset` - Computed relation with `relation` field
- `tuple_to_userset` - Indirect relation with `tupleset` and `computed` fields
- `union` - OR operation
- `intersection` - AND operation
- `exclusion` - EXCEPT operation

**Status Codes**:

- `200 OK` - Expansion completed
- `400 Bad Request` - Invalid request
- `404 Not Found` - Resource or relation not found
- `500 Internal Server Error` - Evaluation error

---

### Write Relationships

Write one or more authorization relationships.

#### Request

```http
POST /write
Content-Type: application/json

{
  "relationships": [
    {
      "resource": "document:readme",
      "relation": "viewer",
      "subject": "user:alice"
    },
    {
      "resource": "document:readme",
      "relation": "editor",
      "subject": "user:bob"
    }
  ]
}
```

**Parameters**:

- `relationships` (array, required): Array of relationships to write
  - `resource` (string): The resource
  - `relation` (string): The relation
  - `subject` (string): The subject

#### Response

```json
{
  "revision": 42
}
```

**Fields**:

- `revision` (number): New revision number after write

**Status Codes**:

- `200 OK` - Relationships written successfully
- `400 Bad Request` - Invalid relationship format
- `500 Internal Server Error` - Write error

#### Example

```bash
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {
        "resource": "document:readme",
        "relation": "viewer",
        "subject": "user:alice"
      }
    ]
  }'
```

Response:

```json
{
  "revision": 1
}
```

---

### Delete Relationships

Delete one or more authorization relationships.

> **Note**: Not yet implemented. Use write endpoint to manage relationships.

---

## Error Responses

All endpoints may return error responses in this format:

```json
{
  "error": "Invalid request",
  "message": "Missing required field 'subject'"
}
```

**Common Error Codes**:

- `400 Bad Request` - Malformed request
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service temporarily unavailable

## Rate Limiting

> **Note**: Rate limiting is not yet implemented.

## Consistency Guarantees

### Read-Your-Writes

After a write, subsequent reads from the same client will see that write:

```bash
# Write relationship
curl -X POST http://localhost:8080/api/v1/write -d '...'
# Returns: {"revision": 5}

# Immediate check will see the write
curl -X POST http://localhost:8080/api/v1/check -d '...'
# Returns: {"decision": "allow"}
```

### Snapshot Reads

> **Note**: Snapshot reads with revision tokens are not yet exposed via REST API.

## Performance Characteristics

**Typical Latencies**:

- `/health`: <1ms
- `/check` (cached): <1ms
- `/check` (uncached, simple): <5ms
- `/check` (uncached, complex): <20ms
- `/expand`: <50ms
- `/write`: <5ms

**Throughput**:

- Sustained: 10k-100k requests/second (depends on cache hit rate)

## Best Practices

### 1. Use Consistent Naming

Use consistent naming conventions for subjects and resources:

```javascript
// Good
const subject = "user:alice";
const resource = "document:readme";

// Avoid
const subject = "alice";
const resource = "readme";
```

### 2. Leverage Caching

The same check will be cached:

```javascript
// First call - queries evaluator
await check({ subject: "user:alice", resource: "doc:1", permission: "view" });

// Second call - hits cache (very fast)
await check({ subject: "user:alice", resource: "doc:1", permission: "view" });
```

### 3. Batch Writes

Batch multiple relationship writes in a single request:

```javascript
// Good - single request
await write({
  relationships: [
    { resource: "doc:1", relation: "viewer", subject: "user:alice" },
    { resource: "doc:1", relation: "editor", subject: "user:bob" },
    { resource: "doc:2", relation: "viewer", subject: "user:alice" },
  ],
});

// Avoid - multiple requests
await write({
  relationships: [{ resource: "doc:1", relation: "viewer", subject: "user:alice" }],
});
await write({
  relationships: [{ resource: "doc:1", relation: "editor", subject: "user:bob" }],
});
await write({
  relationships: [{ resource: "doc:2", relation: "viewer", subject: "user:alice" }],
});
```

### 4. Use Tracing for Debugging

Use `/check/trace` to understand why a check returned a particular decision:

```bash
curl -X POST http://localhost:8080/api/v1/check/trace \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "can_view"
  }' | jq
```

### 5. Handle Errors Gracefully

Always check status codes and handle errors:

```javascript
try {
  const response = await fetch("/api/v1/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ subject, resource, permission }),
  });

  if (!response.ok) {
    const error = await response.json();
    console.error("Check failed:", error.message);
    return false; // Fail closed
  }

  const result = await response.json();
  return result.decision === "allow";
} catch (error) {
  console.error("Network error:", error);
  return false; // Fail closed on errors
}
```

## Client Libraries

### JavaScript/TypeScript

```typescript
class InferaClient {
  constructor(private baseUrl: string) {}

  async check(
    subject: string,
    resource: string,
    permission: string
  ): Promise<boolean> {
    const response = await fetch(`${this.baseUrl}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, resource, permission }),
    });

    const result = await response.json();
    return result.decision === "allow";
  }

  async write(
    relationships: Array<{ resource: string; relation: string; subject: string }>
  ): Promise<number> {
    const response = await fetch(`${this.baseUrl}/write`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ relationships }),
    });

    const result = await response.json();
    return result.revision;
  }
}

// Usage
const client = new InferaClient("http://localhost:8080/api/v1");
const allowed = await client.check("user:alice", "document:readme", "can_view");
```

### Python

```python
import requests
from typing import List, Dict

class InferaClient:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def check(self, subject: str, resource: str, permission: str) -> bool:
        response = requests.post(
            f"{self.base_url}/check",
            json={"subject": subject, "resource": resource, "permission": permission}
        )
        response.raise_for_status()
        return response.json()["decision"] == "allow"

    def write(self, relationships: List[Dict[str, str]]) -> int:
        response = requests.post(
            f"{self.base_url}/write",
            json={"relationships": relationships}
        )
        response.raise_for_status()
        return response.json()["revision"]

# Usage
client = InferaClient("http://localhost:8080/api/v1")
allowed = client.check("user:alice", "document:readme", "can_view")
```

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

type InferaClient struct {
    BaseURL string
}

type CheckRequest struct {
    Subject    string `json:"subject"`
    Resource   string `json:"resource"`
    Permission string `json:"permission"`
}

type CheckResponse struct {
    Decision string `json:"decision"`
}

func (c *InferaClient) Check(subject, resource, permission string) (bool, error) {
    req := CheckRequest{Subject: subject, Resource: resource, Permission: permission}
    body, _ := json.Marshal(req)

    resp, err := http.Post(c.BaseURL+"/check", "application/json", bytes.NewBuffer(body))
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()

    var result CheckResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Decision == "allow", nil
}

// Usage
client := &InferaClient{BaseURL: "http://localhost:8080/api/v1"}
allowed, _ := client.Check("user:alice", "document:readme", "can_view")
```

## Testing

### Using curl

```bash
# Health check
curl http://localhost:8080/api/v1/health

# Write relationships
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{"relationships": [{"resource": "doc:1", "relation": "viewer", "subject": "user:alice"}]}'

# Check permission
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"subject": "user:alice", "resource": "doc:1", "permission": "viewer"}'
```

### Using httpie

```bash
# Health check
http GET :8080/api/v1/health

# Write relationships
http POST :8080/api/v1/write \
  relationships:='[{"resource": "doc:1", "relation": "viewer", "subject": "user:alice"}]'

# Check permission
http POST :8080/api/v1/check \
  subject=user:alice resource=doc:1 permission=viewer
```
