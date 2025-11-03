# Migrating from OpenFGA to InferaDB

This guide helps you migrate from OpenFGA to InferaDB, covering authorization model translation, API mapping, and key architectural differences.

## Why Migrate to InferaDB?

**InferaDB Advantages**:

- ✅ **Streaming APIs**: All operations use streaming for better performance and scalability
- ✅ **Batch Check with Trace**: Industry's only detailed trace on batch operations
- ✅ **No Artificial Limits**: OpenFGA limits batch operations, InferaDB doesn't
- ✅ **Simpler Deployment**: Single binary, no separate store model management
- ✅ **Built-in Auth**: JWT/OAuth with EdDSA/RS256/ES256 (OpenFGA has no built-in auth)
- ✅ **Real-time Watch**: Both gRPC and REST/SSE streaming
- ✅ **WASM Extensibility**: Custom policy logic without changing core

## Quick Comparison

| Feature        | OpenFGA      | InferaDB                          |
| -------------- | ------------ | --------------------------------- |
| Check API      | ✅ Unary     | ✅ Streaming (unlimited batch)    |
| Expand API     | ✅ Unary     | ✅ Server streaming               |
| ListObjects    | ✅ Unary     | ✅ ListResources (streaming)      |
| ListUsers      | ✅ Unary     | ✅ ListSubjects (streaming)       |
| Write          | ✅ Write     | ✅ WriteRelationships (streaming) |
| Read           | ✅ Read      | ✅ ListRelationships (streaming)  |
| Watch          | ✅ Watch     | ✅ Watch (gRPC + SSE)             |
| Wildcards      | ✅ Yes       | ✅ Yes (`type:*`)                 |
| Authentication | ❌ None      | ✅ JWT/OAuth built-in             |
| Store Models   | Separate API | Embedded in schema                |

---

## Authorization Model Migration

### OpenFGA Authorization Model

```json
{
    "schema_version": "1.1",
    "type_definitions": [
        {
            "type": "document",
            "relations": {
                "reader": {
                    "this": {}
                },
                "writer": {
                    "this": {}
                },
                "owner": {
                    "this": {}
                }
            },
            "metadata": {
                "relations": {
                    "viewer": {
                        "directly_related_user_types": [{ "type": "user" }]
                    }
                }
            }
        }
    ]
}
```

### InferaDB Schema (IPL)

```ipl
type document {
    // Direct relations
    relation reader: user
    relation writer: user
    relation owner: user

    // Computed relations (permissions)
    relation viewer: user | reader | writer | owner
    relation editor: user | writer | owner
    relation deleter: user | owner
}
```

### Key Differences

1. **Text-based DSL**: InferaDB uses IPL (Infera Policy Language) instead of JSON
2. **Embedded Schema**: No separate store model API, schema is part of deployment
3. **Simpler Syntax**: Cleaner, more readable format
4. **No Version Field**: Schema versioning handled differently

---

## API Migration Guide

### 1. Check Authorization

**OpenFGA**:

```bash
curl -X POST http://localhost:8080/stores/{store_id}/check \
  -H "Content-Type: application/json" \
  -d '{
    "tuple_key": {
      "user": "user:alice",
      "relation": "viewer",
      "object": "document:readme"
    }
  }'
```

**InferaDB**:

```bash
# REST API - Simpler, no store_id needed
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "viewer"
  }'

# gRPC - Streaming for batch
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "document:readme",
  "permission": "viewer"
}' localhost:8081 infera.v1.InferaService/Evaluate
```

**Key Differences**:

- ✅ No `store_id` parameter (single schema per deployment)
- ✅ Built-in authentication (JWT required)
- ✅ Streaming support for unlimited batch checks
- ✅ Field names: `user→subject`, `object→resource`, `relation→permission`

### 2. Batch Check

**OpenFGA**:

```bash
# Limited batch size
curl -X POST http://localhost:8080/stores/{store_id}/batch-check \
  -d '{
    "checks": [
      {
        "tuple_key": {
          "user": "user:alice",
          "relation": "viewer",
          "object": "document:1"
        }
      }
    ]
  }'
```

**InferaDB**:

```bash
# Unlimited streaming batch
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "document:1",
  "permission": "viewer"
}{
  "subject": "user:alice",
  "resource": "document:2",
  "permission": "viewer"
}' localhost:8081 infera.v1.InferaService/Evaluate
```

**Key Differences**:

- ✅ No batch size limits
- ✅ Streaming handles any number of checks
- ✅ Optional trace for debugging

### 3. Expand Permission Tree

**OpenFGA**:

```bash
curl -X POST http://localhost:8080/stores/{store_id}/expand \
  -d '{
    "tuple_key": {
      "relation": "viewer",
      "object": "document:readme"
    }
  }'
```

**InferaDB**:

```bash
# Server streaming for progressive results
grpcurl -plaintext -d '{
  "resource": "document:readme",
  "relation": "viewer"
}' localhost:8081 infera.v1.InferaService/Expand

# REST API
curl -X POST http://localhost:8080/v1/expand \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "resource": "document:readme",
    "relation": "viewer"
  }'
```

**Key Differences**:

- ✅ Streaming prevents memory issues with large usersets
- ✅ Progressive results as they're computed
- ✅ Better performance for deep hierarchies

### 4. List Objects (ListObjects)

**OpenFGA**:

```bash
curl -X POST http://localhost:8080/stores/{store_id}/list-objects \
  -d '{
    "type": "document",
    "relation": "viewer",
    "user": "user:alice"
  }'
```

**InferaDB**:

```bash
# gRPC - Server streaming
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource_type": "document",
  "permission": "viewer"
}' localhost:8081 infera.v1.InferaService/ListResources

# REST with SSE streaming
curl -X POST http://localhost:8080/v1/resources/list \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "subject": "user:alice",
    "resource_type": "document",
    "permission": "viewer"
  }'
```

**Key Differences**:

- ✅ Renamed to `ListResources` for consistency
- ✅ Streaming handles millions of results
- ✅ REST/SSE option for web clients
- ✅ Optional resource ID pattern filtering

### 5. List Users (New in OpenFGA 1.5+)

**OpenFGA**:

```bash
curl -X POST http://localhost:8080/stores/{store_id}/list-users \
  -d '{
    "object": {
      "type": "document",
      "id": "readme"
    },
    "relation": "viewer",
    "user_filters": [
      {"type": "user"}
    ]
  }'
```

**InferaDB**:

```bash
# gRPC - Server streaming
grpcurl -plaintext -d '{
  "resource": "document:readme",
  "relation": "viewer",
  "subject_type": "user"
}' localhost:8081 infera.v1.InferaService/ListSubjects

# REST with SSE streaming
curl -X POST http://localhost:8080/v1/subjects/list \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "resource": "document:readme",
    "relation": "viewer",
    "subject_type": "user"
  }'
```

**Key Differences**:

- ✅ Renamed to `ListSubjects` for clarity
- ✅ Streaming for large subject lists
- ✅ Simpler request format

### 6. Write Tuples

**OpenFGA**:

```bash
curl -X POST http://localhost:8080/stores/{store_id}/write \
  -d '{
    "writes": {
      "tuple_keys": [
        {
          "user": "user:alice",
          "relation": "reader",
          "object": "document:readme"
        }
      ]
    }
  }'
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
  -H "Authorization: Bearer YOUR_JWT" \
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

- ✅ No separate `writes`/`deletes` wrapper
- ✅ Simpler field names: `tuple_keys→relationships`
- ✅ Streaming for efficient large batches
- ✅ Wildcard support: `"subject": "user:*"`

### 7. Read Tuples

**OpenFGA**:

```bash
curl -X POST http://localhost:8080/stores/{store_id}/read \
  -d '{
    "tuple_key": {
      "user": "user:alice",
      "relation": "reader",
      "object": "document:readme"
    }
  }'
```

**InferaDB**:

```bash
# gRPC - Server streaming
grpcurl -plaintext -d '{
  "resource": "document:readme",
  "relation": "reader",
  "subject": "user:alice"
}' localhost:8081 infera.v1.InferaService/ListRelationships

# REST API
curl -X POST http://localhost:8080/v1/relationships/list \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "resource": "document:readme",
    "relation": "reader",
    "subject": "user:alice"
  }'
```

**Key Differences**:

- ✅ Renamed to `ListRelationships` for clarity
- ✅ Streaming for large result sets
- ✅ All filter fields optional (can query broadly)

### 8. Delete Tuples

**OpenFGA**:

```bash
curl -X POST http://localhost:8080/stores/{store_id}/write \
  -d '{
    "deletes": {
      "tuple_keys": [
        {
          "user": "user:alice",
          "relation": "reader",
          "object": "document:readme"
        }
      ]
    }
  }'
```

**InferaDB**:

```bash
# gRPC - Flexible filtering
grpcurl -plaintext -d '{
  "filter": {
    "resource": "document:readme",
    "relation": "reader",
    "subject": "user:alice"
  }
}' localhost:8081 infera.v1.InferaService/DeleteRelationships

# REST API - Can also delete by exact relationships
curl -X POST http://localhost:8080/v1/delete-relationships \
  -H "Authorization: Bearer YOUR_JWT" \
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

- ✅ Separate delete endpoint (not part of write)
- ✅ Filter-based bulk deletion
- ✅ Safety limits (default 1000, configurable)

### 9. Watch Changes

**OpenFGA**:

```bash
# gRPC only
grpcurl -d '{
  "type": "document"
}' localhost:8081 openfga.v1.OpenFGAService/Watch
```

**InferaDB**:

```bash
# gRPC - Server streaming
grpcurl -plaintext -d '{
  "resource_types": ["document"]
}' localhost:8081 infera.v1.InferaService/Watch

# REST API with Server-Sent Events
curl -X POST http://localhost:8080/v1/watch \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "resource_types": ["document"]
  }'
```

**Key Differences**:

- ✅ REST/SSE option for web applications
- ✅ Cursor-based resumption after disconnection
- ✅ Multiple resource type filters

---

## Store Model vs Schema

### OpenFGA Store Model Management

**OpenFGA requires separate API calls**:

```bash
# 1. Create a store
curl -X POST http://localhost:8080/stores \
  -d '{"name": "my-app"}'

# 2. Write authorization model to store
curl -X POST http://localhost:8080/stores/{store_id}/authorization-models \
  -d '{...authorization model...}'

# 3. All subsequent API calls need store_id
curl -X POST http://localhost:8080/stores/{store_id}/check \
  -d '{...}'
```

### InferaDB Schema Embedded

**InferaDB embeds schema in deployment**:

```bash
# 1. Deploy with schema file
docker run -v ./schema.ipl:/schema.ipl inferadb/server

# 2. All API calls work immediately, no store_id needed
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{...}'
```

**Advantages**:

- ✅ Simpler deployment (one schema per service)
- ✅ No store management overhead
- ✅ Schema versioning via deployment
- ✅ Cleaner API (no store_id everywhere)

---

## Authentication

### OpenFGA

**No built-in authentication** - You must implement:

- Pre-shared key authentication
- Separate API gateway for JWT validation
- Custom middleware for authorization

### InferaDB

**Built-in JWT/OAuth**:

```yaml
# config.yaml
auth:
    enabled: true
    jwks_base_url: "https://your-idp.com/.well-known/jwks.json"
    supported_algorithms: ["EdDSA", "RS256", "ES256"]
    required_scopes:
        - "inferadb.read"
        - "inferadb.write"
```

**Automatic validation**:

```bash
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{...}'
```

---

## Consistency Model

### OpenFGA Consistency Tokens

**OpenFGA**:

```bash
# Get consistency token from write
response=$(curl -X POST .../write ...)
token=$(echo $response | jq -r '.consistency_token')

# Use token in subsequent read
curl -X POST .../check \
  -d '{
    "consistency": "HIGHER_CONSISTENCY",
    "consistency_token": "'$token'",
    ...
  }'
```

### InferaDB Revisions

**InferaDB** provides sequential consistency by default:

```bash
# Write automatically returns revision
response=$(curl -X POST .../write-relationships ...)
revision=$(echo $response | jq -r '.revision')

# All subsequent reads see the write (sequential consistency)
curl -X POST .../check \
  -d '{...}'  # Automatically consistent

# Or specify exact revision if needed
curl -X POST .../check \
  -H "X-Revision: $revision" \
  -d '{...}'
```

**Key Differences**:

- ✅ Sequential consistency by default (no token needed)
- ✅ Simpler integer revisions (not opaque tokens)
- ✅ Optional revision specification via header

---

## Wildcards / Public Access

Both OpenFGA and InferaDB support wildcards.

**OpenFGA**:

```json
{
    "user": "user:*",
    "relation": "viewer",
    "object": "document:readme"
}
```

**InferaDB**:

```json
{
    "subject": "user:*",
    "relation": "viewer",
    "resource": "document:readme"
}
```

**Both support**:

- Public resources (all users can access)
- Type-scoped wildcards (`user:*` matches any user)

---

## Migration Checklist

### 1. Schema Translation

- [ ] Convert OpenFGA JSON model to IPL text format
- [ ] Map `type_definitions` to `type` blocks
- [ ] Convert computed relations format
- [ ] Test schema with sample data

### 2. API Client Updates

- [ ] Remove `store_id` from all API calls
- [ ] Add JWT authentication headers
- [ ] Rename fields: `user→subject`, `object→resource`
- [ ] Update Check to use Evaluate (streaming)
- [ ] Update ListObjects to ListResources
- [ ] Update ListUsers to ListSubjects
- [ ] Update Read to ListRelationships
- [ ] Handle streaming responses

### 3. Store Management Removal

- [ ] Remove store creation logic
- [ ] Remove authorization model write logic
- [ ] Embed schema in deployment configuration
- [ ] Update CI/CD for schema deployment

### 4. Authentication Setup

- [ ] Configure JWT/OAuth provider
- [ ] Set up JWKS endpoint
- [ ] Define required scopes
- [ ] Update client code to include JWT tokens
- [ ] Test authentication flow

### 5. Consistency Model

- [ ] Replace consistency tokens with revisions
- [ ] Update read-after-write logic (simpler now)
- [ ] Test consistency guarantees

### 6. Testing

- [ ] Port integration tests
- [ ] Test with production data sample
- [ ] Performance benchmarking
- [ ] Load testing with streaming APIs

### 7. Deployment

- [ ] Set up InferaDB server (Docker/K8s)
- [ ] Configure storage backend
- [ ] Deploy schema file
- [ ] Set up monitoring
- [ ] Configure multi-region (if needed)

---

## Common Gotchas

### 1. Store ID Everywhere

**OpenFGA**: Every API call needs `store_id`
**InferaDB**: No store concept, single schema per deployment

**Solution**: Remove `store_id` from all API paths and request bodies.

### 2. No Built-in Auth

**OpenFGA**: Must implement your own auth layer
**InferaDB**: JWT/OAuth built-in

**Solution**: Configure InferaDB auth, update clients to send JWT tokens.

### 3. JSON vs Text Schema

**OpenFGA**: Schema is JSON via API
**InferaDB**: Schema is IPL text file in deployment

**Solution**: Convert JSON model to IPL, include in deployment.

### 4. Unary vs Streaming

**OpenFGA**: Most APIs are unary
**InferaDB**: Many APIs stream results

**Solution**: Update client code to handle streaming responses.

### 5. Field Name Changes

**OpenFGA**: `user`, `object`, `tuple_key`
**InferaDB**: `subject`, `resource`, `relationship`

**Solution**: Global find/replace in client code.

---

## Performance Comparison

| Operation   | OpenFGA    | InferaDB  | InferaDB Advantage    |
| ----------- | ---------- | --------- | --------------------- |
| Check       | ~5ms       | ~5ms      | Equal                 |
| BatchCheck  | Limited    | Unlimited | ✅ No limits          |
| Expand      | Buffer all | Streaming | ✅ Memory efficient   |
| ListObjects | Buffer all | Streaming | ✅ Handles millions   |
| ListUsers   | Buffer all | Streaming | ✅ Large subject sets |
| Write       | Good       | Good      | Equal                 |

---

## Support Resources

- **InferaDB Documentation**: [docs/](../README.md)
- **API Reference**: [api/](../../api/README.md)
- **OpenFGA Comparison**: [OPENFGA.md](../../OPENFGA.md)
- **GitHub Issues**: [Issues](https://github.com/inferadb/server/issues)
- **Community**: [Discussions](https://github.com/inferadb/server/discussions)

---

## Need Help?

Migration assistance:

1. **Documentation**: [docs/README.md](../README.md)
2. **API Guide**: [api/README.md](../../api/README.md)
3. **Issues**: [GitHub Issues](https://github.com/inferadb/server/issues)
4. **Community**: [Discussions](https://github.com/inferadb/server/discussions)

We're committed to making your migration seamless! 🚀
