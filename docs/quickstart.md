# Quick Start Guide

Get InferaDB up and running in 5 minutes.

## Prerequisites

- Rust 1.75 or later ([install](https://rustup.rs/))
- Git

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/inferadb.git
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

### Step 2: Write Tuples

Grant some permissions:

```bash
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{
    "tuples": [
      {"object": "document:readme", "relation": "viewer", "user": "user:alice"},
      {"object": "document:readme", "relation": "editor", "user": "user:bob"},
      {"object": "document:readme", "relation": "owner", "user": "user:charlie"}
    ]
  }'
```

Response:

```json
{ "revision": 1 }
```

### Step 3: Check Permission

Check if Alice can view the document:

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
{ "decision": "allow" }
```

Check if Alice can delete (she can't):

```bash
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "can_delete"
  }'
```

Response:

```json
{ "decision": "deny" }
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
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{
    "tuples": [
      {"object": "folder:root", "relation": "viewer", "user": "user:alice"},
      {"object": "folder:sub", "relation": "parent", "user": "folder:root"},
      {"object": "document:readme", "relation": "parent", "user": "folder:sub"}
    ]
  }'
```

### Check Inherited Permission

Alice is a viewer of root folder, so she can view documents in sub folder:

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
{ "decision": "allow" }
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
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{
    "tuples": [
      {"object": "organization:org1", "relation": "member", "user": "user:alice"},
      {"object": "project:proj1", "relation": "org", "user": "organization:org1"}
    ]
  }'

# Alice can view proj1 (member of org)
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "project:proj1",
    "permission": "can_view"
  }'
# Returns: {"decision": "allow"}
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
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{
    "tuples": [
      {"object": "document:secret", "relation": "viewer", "user": "user:alice"},
      {"object": "document:secret", "relation": "blocked", "user": "user:alice"}
    ]
  }'

# Alice cannot view (blocked takes precedence)
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:secret",
    "permission": "can_view"
  }'
# Returns: {"decision": "deny"}
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
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{
    "tuples": [
      {"object": "document:classified", "relation": "viewer", "user": "user:alice"}
    ]
  }'

# Alice cannot view (needs both)
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:classified",
    "permission": "can_view"
  }'
# Returns: {"decision": "deny"}

# Grant clearance
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{
    "tuples": [
      {"object": "document:classified", "relation": "clearance", "user": "user:alice"}
    ]
  }'

# Now Alice can view
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:classified",
    "permission": "can_view"
  }'
# Returns: {"decision": "allow"}
```

## Debugging

### Use Trace to Understand Decisions

```bash
curl -X POST http://localhost:8080/api/v1/check/trace \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "can_view"
  }' | jq
```

Response shows evaluation tree:

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

### "Invalid tuple format"

Check that tuples have all required fields:

```json
{
  "object": "resource:id", // Required
  "relation": "relation_name", // Required
  "user": "subject:id" // Required
}
```

### "Decision is deny but should be allow"

1. Check tuples are written correctly:

   ```bash
   # List doesn't exist yet, but you can verify via check
   ```

2. Use trace to see evaluation:

   ```bash
   curl -X POST http://localhost:8080/api/v1/check/trace ...
   ```

3. Verify schema definition matches expected behavior

## Performance Tips

1. **Batch writes** - Write multiple tuples in one request
2. **Cache hits** - Repeated checks are cached (very fast)
3. **Simple schemas** - Fewer indirections = faster evaluation
4. **Direct relations** - Use `this` when possible instead of computed relations

## Testing Your Integration

### Bash Script Example

```bash
#!/bin/bash
set -e

API="http://localhost:8080/api/v1"

# Write tuples
echo "Writing tuples..."
curl -s -X POST $API/write \
  -H "Content-Type: application/json" \
  -d '{"tuples": [{"object": "doc:1", "relation": "viewer", "user": "user:alice"}]}' \
  > /dev/null

# Check permission
echo "Checking permission..."
RESULT=$(curl -s -X POST $API/check \
  -H "Content-Type: application/json" \
  -d '{"subject": "user:alice", "resource": "doc:1", "permission": "viewer"}')

DECISION=$(echo $RESULT | jq -r '.decision')

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

API_BASE = "http://localhost:8080/api/v1"

# Write tuple
response = requests.post(
    f"{API_BASE}/write",
    json={
        "tuples": [
            {"object": "doc:1", "relation": "viewer", "user": "user:alice"}
        ]
    }
)
print(f"Write: {response.json()}")

# Check permission
response = requests.post(
    f"{API_BASE}/check",
    json={
        "subject": "user:alice",
        "resource": "doc:1",
        "permission": "viewer"
    }
)
decision = response.json()["decision"]
print(f"Check: {decision}")

assert decision == "allow", "Expected allow"
print("✓ Test passed")
```

## Explore Further

- [Complete API Reference](api-rest.md)
- [IPL Language Guide](core/ipl.md)
- [gRPC API](api-grpc.md)
- [WASM Integration](wasm-integration.md)
- [Caching System](caching.md)
