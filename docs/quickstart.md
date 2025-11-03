# Quick Start Guide

Get InferaDB up and running in 5 minutes.

## Prerequisites

- Rust 1.75 or later ([install](https://rustup.rs/))
- Git

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/inferadb/server.git
cd inferadb/server
```

### 2. Build

```bash
cargo build --release
```

### 3. Run

```bash
cargo run --release
```

The server starts on `http://localhost:8080`.

## Your First Authorization Check

### Step 1: Define a Schema

Create a file `schema.ipl`:

```ipl
type document {
    relation viewer
    relation editor
    relation owner

    relation can_view = viewer | editor | owner
    relation can_edit = editor | owner
    relation can_delete = owner
}
```

### Step 2: Write Relationships

Grant some permissions:

```bash
curl -X POST http://localhost:8080/v1/relationships/write \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {"resource": "document:readme", "relation": "viewer", "subject": "user:alice"},
      {"resource": "document:readme", "relation": "editor", "subject": "user:bob"},
      {"resource": "document:readme", "relation": "owner", "subject": "user:charlie"}
    ]
  }'
```

Response:

```json
{ "revision": "1", "relationships_written": 3 }
```

### Step 3: Check Permission

Check if Alice can view the document:

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "document:readme",
        "permission": "can_view"
      }
    ]
  }'
```

Response:

```json
{ "results": [{ "decision": "allow" }] }
```

Check if Alice can delete (she can't):

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "document:readme",
        "permission": "can_delete"
      }
    ]
  }'
```

Response:

```json
{ "results": [{ "decision": "deny" }] }
```

## Example: Document Hierarchy

### Schema

```ipl
type folder {
    relation viewer
    relation parent: folder

    relation can_view = viewer | viewer from parent
}

type document {
    relation viewer
    relation parent: folder

    relation can_view = viewer | can_view from parent
}
```

### Setup

```bash
# Create folder hierarchy: root -> sub
curl -X POST http://localhost:8080/v1/relationships/write \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {"resource": "folder:root", "relation": "viewer", "subject": "user:alice"},
      {"resource": "folder:sub", "relation": "parent", "subject": "folder:root"},
      {"resource": "document:readme", "relation": "parent", "subject": "folder:sub"}
    ]
  }'
```

### Check Inherited Permission

Alice is a viewer of root folder, so she can view documents in sub folder:

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "document:readme",
        "permission": "can_view"
      }
    ]
  }'
```

Response:

```json
{ "results": [{ "decision": "allow" }] }
```

## Common Patterns

### Pattern 1: Role-Based Access

```ipl
type organization {
    relation member
    relation admin
}

type project {
    relation org: organization

    relation can_view = member from org
    relation can_admin = admin from org
}
```

```bash
# Make Alice a member of org1
curl -X POST http://localhost:8080/v1/relationships/write \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {"resource": "organization:org1", "relation": "member", "subject": "user:alice"},
      {"resource": "project:proj1", "relation": "org", "subject": "organization:org1"}
    ]
  }'

# Alice can view proj1 (member of org)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "project:proj1",
        "permission": "can_view"
      }
    ]
  }'
# Returns: {"results": [{"decision": "allow"}]}
```

### Pattern 2: Exclusion (Blocking)

```ipl
type document {
    relation viewer
    relation blocked

    relation can_view = viewer - blocked
}
```

```bash
# Alice is a viewer but also blocked
curl -X POST http://localhost:8080/v1/relationships/write \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {"resource": "document:secret", "relation": "viewer", "subject": "user:alice"},
      {"resource": "document:secret", "relation": "blocked", "subject": "user:alice"}
    ]
  }'

# Alice cannot view (blocked takes precedence)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "document:secret",
        "permission": "can_view"
      }
    ]
  }'
# Returns: {"results": [{"decision": "deny"}]}
```

### Pattern 3: Intersection (Multiple Requirements)

```ipl
type document {
    relation viewer
    relation clearance

    relation can_view = viewer & clearance
}
```

```bash
# Alice has viewer but not clearance
curl -X POST http://localhost:8080/v1/relationships/write \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {"resource": "document:classified", "relation": "viewer", "subject": "user:alice"}
    ]
  }'

# Alice cannot view (needs both)
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "document:classified",
        "permission": "can_view"
      }
    ]
  }'
# Returns: {"results": [{"decision": "deny"}]}

# Grant clearance
curl -X POST http://localhost:8080/v1/relationships/write \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {"resource": "document:classified", "relation": "clearance", "subject": "user:alice"}
    ]
  }'

# Now Alice can view
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "document:classified",
        "permission": "can_view"
      }
    ]
  }'
# Returns: {"results": [{"decision": "allow"}]}
```

## Debugging

### Use Trace to Understand Decisions

Add `"trace": true` to the evaluation request to see the decision tree:

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "document:readme",
        "permission": "can_view"
      }
    ],
    "trace": true
  }' | jq
```

Response shows evaluation tree:

```json
{
    "results": [
        {
            "decision": "allow",
            "trace": {
                "decision": "allow",
                "node_type": "union",
                "children": [
                    {
                        "decision": "allow",
                        "node_type": "direct",
                        "relation": "viewer"
                    },
                    {
                        "decision": "deny",
                        "node_type": "computed_userset",
                        "relation": "editor"
                    },
                    {
                        "decision": "deny",
                        "node_type": "computed_userset",
                        "relation": "owner"
                    }
                ]
            }
        }
    ]
}
```

This shows: Alice has `can_view` because she's a direct `viewer`.

## Next Steps

1. **Read the [IPL Language Guide](core/ipl.md)** to learn the full policy language
2. **Explore the [Architecture](architecture.md)** to understand how InferaDB works
3. **Check the [API Reference](api-rest.md)** for complete API documentation
4. **See [Building from Source](building.md)** for development setup

## Common Issues

### "Connection refused"

Ensure the server is running:

```bash
cargo run --release
```

### "Invalid relationship format"

Check that relationships have all required fields:

```json
{
    "resource": "resource:id", // Required
    "relation": "relation_name", // Required
    "subject": "subject:id" // Required
}
```

### "Decision is deny but should be allow"

1. Check relationships are written correctly by listing them

2. Use trace to see evaluation:

    ```bash
    curl -X POST http://localhost:8080/v1/evaluate \
      -H "Content-Type: application/json" \
      -d '{"evaluations": [...], "trace": true}'
    ```

3. Verify schema definition matches expected behavior

## Performance Tips

1. **Batch writes** - Write multiple relationships in one request
2. **Cache hits** - Repeated evaluations are cached (very fast)
3. **Simple schemas** - Fewer indirections = faster evaluation
4. **Direct relations** - Use `this` when possible instead of computed relations

## Testing Your Integration

### Bash Script Example

```bash
#!/bin/bash
set -e

API="http://localhost:8080/v1"

# Write relationships
echo "Writing relationships..."
curl -s -X POST $API/relationships/write \
  -H "Content-Type: application/json" \
  -d '{"relationships": [{"resource": "doc:1", "relation": "viewer", "subject": "user:alice"}]}' \
  > /dev/null

# Check permission
echo "Checking permission..."
RESULT=$(curl -s -X POST $API/evaluate \
  -H "Content-Type: application/json" \
  -d '{"evaluations": [{"subject": "user:alice", "resource": "doc:1", "permission": "viewer"}]}')

DECISION=$(echo $RESULT | jq -r '.results[0].decision')

if [ "$DECISION" = "allow" ]; then
  echo "✓ Test passed"
  exit 0
else
  echo "✗ Test failed: expected allow, got $DECISION"
  exit 1
fi
```

### Python Script Example

```python
import requests

API_BASE = "http://localhost:8080/v1"

# Write relationship
response = requests.post(
    f"{API_BASE}/relationships/write",
    json={
        "relationships": [
            {"resource": "doc:1", "relation": "viewer", "subject": "user:alice"}
        ]
    }
)
print(f"Write: {response.json()}")

# Check permission
response = requests.post(
    f"{API_BASE}/evaluate",
    json={
        "evaluations": [
            {
                "subject": "user:alice",
                "resource": "doc:1",
                "permission": "viewer"
            }
        ]
    }
)
decision = response.json()["results"][0]["decision"]
print(f"Check: {decision}")

assert decision == "allow", "Expected allow"
print("✓ Test passed")
```

## AuthZEN-Compliant API

InferaDB implements the OpenID Foundation's AuthZEN specification for standardized authorization APIs. Use AuthZEN endpoints for interoperability with other AuthZEN-compliant systems.

### AuthZEN Single Evaluation

Check if a subject can perform an action on a resource:

```bash
curl -X POST http://localhost:8080/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "alice"},
    "action": {"name": "view"},
    "resource": {"type": "document", "id": "readme"}
  }'
```

Response:

```json
{
    "decision": true
}
```

### AuthZEN Batch Evaluations

Check multiple permissions in one request:

```bash
curl -X POST http://localhost:8080/access/v1/evaluations \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": {"type": "user", "id": "alice"},
        "action": {"name": "view"},
        "resource": {"type": "document", "id": "readme"}
      },
      {
        "subject": {"type": "user", "id": "alice"},
        "action": {"name": "edit"},
        "resource": {"type": "document", "id": "readme"}
      }
    ]
  }'
```

Response:

```json
{
    "evaluations": [{ "decision": true }, { "decision": false }]
}
```

### AuthZEN Search

Find all resources a subject can access:

```bash
curl -X POST http://localhost:8080/access/v1/search/resource \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "alice"},
    "action": {"name": "view"},
    "resource_type": "document"
  }'
```

Response:

```json
{
    "resources": [
        { "type": "document", "id": "readme" },
        { "type": "document", "id": "guide" }
    ]
}
```

### Service Discovery

Discover InferaDB's AuthZEN capabilities:

```bash
curl http://localhost:8080/.well-known/authzen-configuration
```

Response shows available endpoints and extensions:

```json
{
    "issuer": "http://127.0.0.1:8080",
    "access_evaluation_endpoint": "http://127.0.0.1:8080/access/v1/evaluation",
    "access_evaluations_endpoint": "http://127.0.0.1:8080/access/v1/evaluations",
    "search_resource_endpoint": "http://127.0.0.1:8080/access/v1/search/resource",
    "search_subject_endpoint": "http://127.0.0.1:8080/access/v1/search/subject",
    "extensions": {
        "inferadb_relationship_management": true,
        "inferadb_relation_expansion": true,
        "inferadb_simulation": true,
        "inferadb_realtime_streaming": true
    }
}
```

## Explore Further

- [Complete API Reference](api-rest.md)
- [AuthZEN Extensions Documentation](../docs/api/authzen-extensions.md)
- [AuthZEN Data Model Mapping](../docs/api/authzen-mapping.md)
- [IPL Language Guide](core/ipl.md)
- [gRPC API](api-grpc.md)
- [WASM Integration](wasm-integration.md)
- [Caching System](caching.md)
