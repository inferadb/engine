# Migrating from SpiceDB to InferaDB

This guide helps you migrate from SpiceDB to InferaDB, highlighting API equivalents, schema translation, and key differences.

## Why Migrate to InferaDB?

**InferaDB Advantages**:

- ✅ **Streaming APIs**: All list operations stream results for better performance
- ✅ **Batch Check with Trace**: Industry's only platform with detailed trace on batch checks
- ✅ **No Hard Limits**: SpiceDB limits BatchCheck to 30-100 items, InferaDB has no limit
- ✅ **Simpler API**: Unified streaming pattern across all operations
- ✅ **Built-in Auth**: JWT/OAuth with EdDSA/RS256/ES256 support
- ✅ **Real-time Watch**: gRPC + REST/SSE streaming for change events
- ✅ **Wildcards**: `type:*` pattern for public access modeling

## Quick Comparison

| Feature       | SpiceDB                | InferaDB                           |
| ------------- | ---------------------- | ---------------------------------- |
| Check API     | ✅ Unary               | ✅ Streaming (batch unlimited)     |
| Expand API    | ✅ Unary               | ✅ Server streaming                |
| ListResources | ✅ LookupResources     | ✅ ListResources (streaming)       |
| ListSubjects  | ✅ LookupSubjects      | ✅ ListSubjects (streaming)        |
| Write         | ✅ WriteRelationships  | ✅ WriteRelationships (streaming)  |
| Delete        | ✅ DeleteRelationships | ✅ DeleteRelationships (streaming) |
| Watch         | ✅ Watch               | ✅ Watch (gRPC + SSE)              |
| Wildcards     | ✅ Yes                 | ✅ Yes (`type:*`)                  |
| Batch Limit   | ⚠️ 30-100 checks       | ✅ Unlimited                       |

---

## Schema Migration

### SpiceDB Schema (Authzed Schema Language)

```
definition document {
    relation reader: user
    relation writer: user
    relation owner: user

    permission view = reader + writer + owner
    permission edit = writer + owner
    permission delete = owner
}

definition folder {
    relation parent: folder
    relation viewer: user

    permission view = viewer + parent->view
}
```

### InferaDB Schema (IPL - Infera Policy Language)

```ipl
type document {
    relation reader: user
    relation writer: user
    relation owner: user

    relation viewer: user | reader | writer | owner
    relation editor: user | writer | owner
    relation deleter: user | owner
}

type folder {
    relation parent: folder
    relation viewer: user

    relation view: user | viewer | parent->view
}
```

### Key Differences

1. **`permission` → `relation`**: InferaDB uses `relation` for both direct and computed relations
2. **Type syntax**: InferaDB uses `type` instead of `definition`
3. **Union operator**: Both use `|` or `+` for union
4. **Arrow operator**: Both use `->` for relation traversal

---

## API Migration

### 1. Check Permission

**SpiceDB**:

```bash
# gRPC
grpcurl -d '{
  "resource": {
    "object_type": "document",
    "object_id": "readme"
  },
  "permission": "view",
  "subject": {
    "object": {
      "object_type": "user",
      "object_id": "alice"
    }
  }
}' localhost:50051 authzed.api.v1.PermissionsService/CheckPermission
```

**InferaDB**:

```bash
# gRPC - Simpler format, streaming for batch
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "document:readme",
  "permission": "view"
}' localhost:8081 infera.v1.InferaService/Evaluate

# REST API also available
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "view"
  }'
```

**Key Differences**:

- ✅ InferaDB uses simple string format: `type:id`
- ✅ InferaDB has both gRPC and REST APIs
- ✅ InferaDB supports streaming for unlimited batch checks

### 2. Batch Check

**SpiceDB**:

```bash
# Limited to 30-100 items
grpcurl -d '{
  "items": [
    {
      "resource": {"object_type": "document", "object_id": "1"},
      "permission": "view",
      "subject": {"object": {"object_type": "user", "object_id": "alice"}}
    }
  ]
}' localhost:50051 authzed.api.v1.ExperimentalService/BulkCheckPermission
```

**InferaDB**:

```bash
# Unlimited items via streaming
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "document:1",
  "permission": "view"
}{
  "subject": "user:alice",
  "resource": "document:2",
  "permission": "view"
}' localhost:8081 infera.v1.InferaService/Evaluate
```

**Key Differences**:

- ✅ No hard limits in InferaDB
- ✅ Streaming design handles unlimited batch size
- ✅ Better performance for large batches

### 3. Expand Relation

**SpiceDB**:

```bash
grpcurl -d '{
  "resource": {
    "object_type": "document",
    "object_id": "readme"
  },
  "permission": "view"
}' localhost:50051 authzed.api.v1.PermissionsService/ExpandPermissionTree
```

**InferaDB**:

```bash
# Server streaming for progressive results
grpcurl -plaintext -d '{
  "resource": "document:readme",
  "relation": "view"
}' localhost:8081 infera.v1.InferaService/Expand
```

**Key Differences**:

- ✅ InferaDB streams results progressively
- ✅ Simpler request format
- ✅ Better performance for large usersets

### 4. List Resources (LookupResources)

**SpiceDB**:

```bash
grpcurl -d '{
  "resource_object_type": "document",
  "permission": "view",
  "subject": {
    "object": {
      "object_type": "user",
      "object_id": "alice"
    }
  }
}' localhost:50051 authzed.api.v1.PermissionsService/LookupResources
```

**InferaDB**:

```bash
# gRPC - Server streaming
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource_type": "document",
  "permission": "view"
}' localhost:8081 infera.v1.InferaService/ListResources

# REST API with SSE streaming
curl -X POST http://localhost:8080/v1/resources/list \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource_type": "document",
    "permission": "view"
  }'
```

**Key Differences**:

- ✅ Streaming prevents memory issues with large result sets
- ✅ REST/SSE option for web clients
- ✅ Optional resource ID pattern filtering

### 5. List Subjects (LookupSubjects)

**SpiceDB**:

```bash
grpcurl -d '{
  "resource": {
    "object_type": "document",
    "object_id": "readme"
  },
  "permission": "view",
  "subject_object_type": "user"
}' localhost:50051 authzed.api.v1.PermissionsService/LookupSubjects
```

**InferaDB**:

```bash
# gRPC - Server streaming
grpcurl -plaintext -d '{
  "resource": "document:readme",
  "relation": "view",
  "subject_type": "user"
}' localhost:8081 infera.v1.InferaService/ListSubjects

# REST API with SSE streaming
curl -X POST http://localhost:8080/v1/subjects/list \
  -H "Content-Type: application/json" \
  -d '{
    "resource": "document:readme",
    "relation": "view",
    "subject_type": "user"
  }'
```

### 6. Write Relationships

**SpiceDB**:

```bash
grpcurl -d '{
  "updates": [
    {
      "operation": "OPERATION_CREATE",
      "relationship": {
        "resource": {"object_type": "document", "object_id": "readme"},
        "relation": "reader",
        "subject": {"object": {"object_type": "user", "object_id": "alice"}}
      }
    }
  ]
}' localhost:50051 authzed.api.v1.PermissionsService/WriteRelationships
```

**InferaDB**:

```bash
# gRPC - Client streaming for batch
grpcurl -plaintext -d '{
  "relationships": [
    {
      "resource": "document:readme",
      "relation": "reader",
      "subject": "user:alice"
    }
  ]
}' localhost:8081 infera.v1.InferaService/WriteRelationships

# REST API
curl -X POST http://localhost:8080/v1/write-relationships \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {
        "resource": "document:readme",
        "relation": "reader",
        "subject": "user:alice"
      }
    ]
  }'
```

**Key Differences**:

- ✅ Simpler format (no operation field needed)
- ✅ Streaming for efficient batch writes
- ✅ Wildcard support: `"subject": "user:*"` for public access

### 7. Delete Relationships

**SpiceDB**:

```bash
grpcurl -d '{
  "relationship_filter": {
    "resource_type": "document",
    "optional_resource_id": "readme",
    "optional_relation": "reader"
  }
}' localhost:50051 authzed.api.v1.PermissionsService/DeleteRelationships
```

**InferaDB**:

```bash
# gRPC - More flexible filtering
grpcurl -plaintext -d '{
  "filter": {
    "resource": "document:readme",
    "relation": "reader"
  }
}' localhost:8081 infera.v1.InferaService/DeleteRelationships

# REST API
curl -X POST http://localhost:8080/v1/delete-relationships \
  -H "Content-Type: application/json" \
  -d '{
    "filter": {
      "resource": "document:readme",
      "relation": "reader"
    }
  }'
```

### 8. Watch Changes

**SpiceDB**:

```bash
grpcurl -d '{
  "optional_object_type": "document"
}' localhost:50051 authzed.api.v1.WatchService/Watch
```

**InferaDB**:

```bash
# gRPC - Server streaming
grpcurl -plaintext -d '{
  "resource_types": ["document"]
}' localhost:8081 infera.v1.InferaService/Watch

# REST API with Server-Sent Events
curl -X POST http://localhost:8080/v1/watch \
  -H "Content-Type: application/json" \
  -d '{
    "resource_types": ["document"]
  }'
```

**Key Differences**:

- ✅ REST/SSE option for web applications
- ✅ Cursor-based resumption
- ✅ Simpler filtering

---

## Consistency Model

### SpiceDB Zookies

**SpiceDB**:

```bash
# Read your writes with Zookie
response=$(grpcurl -d '{...}' localhost:50051 .../WriteRelationships)
zookie=$(echo $response | jq -r '.written_at.token')

# Use Zookie in subsequent read
grpcurl -d '{
  "consistency": {
    "at_least_as_fresh": {"token": "'$zookie'"}
  },
  ...
}' localhost:50051 .../CheckPermission
```

**InferaDB**:

```bash
# Simpler revision-based consistency
response=$(curl -X POST http://localhost:8080/v1/write-relationships ...)
revision=$(echo $response | jq -r '.revision')

# All reads automatically see writes (sequential consistency)
# Or specify exact revision if needed
curl -X POST http://localhost:8080/v1/evaluate \
  -H "X-Revision: $revision" \
  ...
```

**Key Differences**:

- ✅ InferaDB provides sequential consistency by default
- ✅ Simpler revision tokens (integer, not opaque token)
- ✅ Optional revision specification via header

---

## Wildcards / Public Access

Both SpiceDB and InferaDB support wildcards for modeling public resources.

**SpiceDB**:

```
document:readme#reader@user:*
```

**InferaDB**:

```json
{
    "resource": "document:readme",
    "relation": "reader",
    "subject": "user:*"
}
```

**Both support**:

- Public resources (all users can access)
- Type-scoped wildcards (`user:*` matches any user)

---

## Migration Checklist

### 1. Schema Translation

- [ ] Convert `definition` to `type`
- [ ] Convert `permission` to computed `relation`
- [ ] Test schema with sample data

### 2. Client Code Updates

- [ ] Replace nested object format with `type:id` strings
- [ ] Update Check calls to use Evaluate (streaming)
- [ ] Update LookupResources to ListResources
- [ ] Update LookupSubjects to ListSubjects
- [ ] Handle streaming responses in list operations

### 3. Consistency Model

- [ ] Replace Zookies with revision tokens
- [ ] Update consistency guarantees (default sequential)
- [ ] Test read-after-write scenarios

### 4. Authentication

- [ ] Configure JWT/OAuth (SpiceDB uses pre-shared keys)
- [ ] Set up JWKS endpoint or inline keys
- [ ] Configure required scopes

### 5. Testing

- [ ] Port integration tests
- [ ] Test with production data sample
- [ ] Performance benchmarking
- [ ] Load testing

### 6. Deployment

- [ ] Set up InferaDB server (Docker/K8s)
- [ ] Configure storage backend (Memory/FoundationDB)
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure multi-region replication (if needed)

---

## Common Gotchas

### 1. Object Format

**SpiceDB**: Nested object structure

```json
{
    "object_type": "document",
    "object_id": "readme"
}
```

**InferaDB**: Simple string format

```json
"document:readme"
```

### 2. Streaming vs Unary

**SpiceDB**: Most APIs are unary (single request/response)
**InferaDB**: Many APIs are streaming (progressive results)

**Solution**: Update client code to handle streaming responses.

### 3. Batch Check Limits

**SpiceDB**: Hard limit of 30-100 checks per batch
**InferaDB**: No limit (streaming handles any size)

**Solution**: Remove batching logic, send all checks in stream.

### 4. Schema Syntax

**SpiceDB**: Uses `permission` for computed relations
**InferaDB**: Uses `relation` for both direct and computed

**Solution**: Simple find/replace in schema files.

---

## Performance Comparison

| Operation        | SpiceDB      | InferaDB  | InferaDB Advantage  |
| ---------------- | ------------ | --------- | ------------------- |
| Check (cached)   | <1ms         | <1ms      | Equal               |
| Check (uncached) | 3-5ms        | 3-5ms     | Equal               |
| BatchCheck       | 30-100 limit | Unlimited | ✅ No limits        |
| Expand           | Buffer all   | Streaming | ✅ Memory efficient |
| LookupResources  | Buffer all   | Streaming | ✅ Handles millions |
| Write batch      | Good         | Good      | Equal               |

---

## Support Resources

- **InferaDB Documentation**: [docs/](../README.md)
- **API Reference**: [api/](../../api/README.md)
- **SpiceDB Comparison**: [COMPARISON.md](../../COMPARISON.md)
- **GitHub Issues**: [Issues](https://github.com/inferadb/server/issues)
- **Community**: [Discussions](https://github.com/inferadb/server/discussions)

---

## Need Help?

If you encounter issues during migration:

1. **Check the docs**: [docs/README.md](../README.md)
2. **Search issues**: [GitHub Issues](https://github.com/inferadb/server/issues)
3. **Ask the community**: [Discussions](https://github.com/inferadb/server/discussions)
4. **Report bugs**: [New Issue](https://github.com/inferadb/server/issues/new)

We're here to help make your migration smooth! 🚀
