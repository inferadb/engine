# InferaDB API Documentation

Welcome to the InferaDB API documentation. InferaDB provides both REST and gRPC APIs for authorization checks and relationship management.

## Quick Navigation

### 🚀 Interactive API Explorers

Get hands-on with the APIs:

- **[REST API Explorer (Swagger UI)](./swagger-ui.html)** - Interactive REST API testing with Swagger UI
- **[gRPC API Explorer](./grpc-explorer.html)** - Interactive gRPC API testing with grpcui

### 📖 API Reference Documentation

Detailed API documentation:

- **[REST API Reference](./rest.md)** - Complete REST API documentation with examples
- **[gRPC API Reference](./grpc.md)** - Complete gRPC API documentation with examples

### 📋 API Specifications

Machine-readable API definitions:

- **[OpenAPI Specification (openapi.yaml)](./openapi.yaml)** - OpenAPI 3.1 spec for REST API
- **[Protocol Buffer Definition](../crates/infera-api/proto/infera.proto)** - Proto file for gRPC API

## Getting Started

### REST API

The REST API is perfect for:
- Quick prototyping
- Web applications
- Simple integrations
- Testing and debugging

**Base URL**: `http://localhost:8080/api/v1`

**Quick example**:
```bash
# Check if user:alice can view document:readme
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "can_view"
  }'
```

**Try it interactively**: Open [swagger-ui.html](./swagger-ui.html) in your browser

### gRPC API

The gRPC API is ideal for:
- Production deployments
- High-performance requirements
- Low-latency applications
- Microservices architectures

**Server Address**: `localhost:8081`

**Quick example**:
```bash
# Check permission (using grpcurl)
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "document:readme",
  "permission": "viewer"
}' localhost:8081 infera.v1.InferaService/Check
```

**Try it interactively**: Follow the guide at [grpc-explorer.html](./grpc-explorer.html)

## API Features

### Core Operations

Both APIs support these operations:

**Authorization Checks**:
- **Check** - Check if a subject has permission on a resource (streaming for batch)
- **CheckWithTrace** - Check with detailed evaluation trace for debugging

**Query Operations**:
- **Expand** - Expand a relation to see all users who have access (streaming)
- **ListResources** - List all resources a subject can access (streaming)
- **ListSubjects** - List all subjects that have access to a resource (streaming)
- **ListRelationships** - List relationships with optional filtering (streaming)

**Data Operations**:
- **Write** - Write authorization relationships (streaming for batch)
- **Delete** - Delete authorization relationships (streaming for batch)

**Real-time**:
- **Watch** - Stream real-time relationship change events (SSE/gRPC streaming)

**System**:
- **Health** - Check service health

### Performance

Typical latencies (REST API):
- Health check: <1ms
- Permission check (cached): <1ms
- Permission check (simple): <5ms
- Permission check (complex): <20ms
- Expand relation: <50ms
- Write relationships: <5ms

The gRPC API is typically 20-30% faster due to binary protocol overhead.

### Authentication

InferaDB uses JWT (JSON Web Token) authentication. See the [Authentication Guide](../docs/security/authentication.md) for details on:
- Creating JWTs
- Supported algorithms (EdDSA, RS256, ES256)
- OIDC Discovery
- OAuth 2.0 integration

**Quick auth example**:
```bash
# Include JWT in Authorization header
curl -X POST http://localhost:8080/api/v1/check \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject":"user:alice","resource":"doc:1","permission":"viewer"}'
```

## Client Libraries

### Generate gRPC Clients

The proto file can generate clients for many languages:

```bash
# Go
protoc --go_out=. --go-grpc_out=. infera.proto

# Python
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. infera.proto

# Java
protoc --java_out=. --grpc-java_out=. infera.proto

# Rust
Use tonic-build in build.rs
```

See [gRPC API Reference](./grpc.md) for complete client generation examples.

### REST Client Examples

Simple REST clients are available in the [REST API Reference](./rest.md) for:
- JavaScript/TypeScript
- Python
- Go
- cURL

## Tools

### REST API Tools

- **[Swagger UI](./swagger-ui.html)** - Built-in interactive API explorer
- **curl** - Command-line HTTP client
- **httpie** - User-friendly HTTP client
- **Postman** - GUI API testing tool

### gRPC API Tools

- **[grpcui](./grpc-explorer.html)** - Interactive web UI for gRPC (recommended)
- **grpcurl** - Command-line gRPC client (like curl for gRPC)
- **BloomRPC** - GUI gRPC client (like Postman for gRPC)
- **Postman** - Now supports gRPC natively

Install grpcui:
```bash
# macOS
brew install grpcui

# Other platforms
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest

# Start grpcui
grpcui -plaintext localhost:8081
```

## Testing the API

### 1. Start InferaDB

```bash
# Docker
docker run -p 8080:8080 -p 8081:8081 inferadb/server:latest

# From source
cargo run --release
```

### 2. Write Test Data

```bash
# REST API
curl -X POST http://localhost:8080/api/v1/write \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [
      {"resource": "doc:1", "relation": "viewer", "subject": "user:alice"},
      {"resource": "doc:1", "relation": "editor", "subject": "user:bob"}
    ]
  }'

# gRPC API
grpcurl -plaintext -d '{
  "relationships": [
    {"resource": "doc:1", "relation": "viewer", "subject": "user:alice"}
  ]
}' localhost:8081 infera.v1.InferaService/Write
```

### 3. Test Permission Checks

```bash
# REST API
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"subject": "user:alice", "resource": "doc:1", "permission": "viewer"}'

# gRPC API
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "doc:1",
  "permission": "viewer"
}' localhost:8081 infera.v1.InferaService/Check
```

### 4. Debug with Trace

```bash
# REST API
curl -X POST http://localhost:8080/api/v1/check/trace \
  -H "Content-Type: application/json" \
  -d '{"subject": "user:alice", "resource": "doc:1", "permission": "viewer"}' | jq

# gRPC API
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "doc:1",
  "permission": "viewer"
}' localhost:8081 infera.v1.InferaService/CheckWithTrace | jq
```

## Error Handling

Both APIs return consistent error responses:

### REST API Errors

```json
{
  "error": "Invalid request",
  "message": "Missing required field 'subject'"
}
```

Common HTTP status codes:
- `200 OK` - Success
- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Authentication required
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

### gRPC API Errors

gRPC uses standard status codes:
- `OK` - Success
- `INVALID_ARGUMENT` - Invalid request parameters
- `UNAUTHENTICATED` - Authentication required
- `NOT_FOUND` - Resource not found
- `RESOURCE_EXHAUSTED` - Rate limit exceeded
- `INTERNAL` - Server error

## Best Practices

### 1. Use Consistent Naming

```javascript
// Good
const subject = "user:alice";
const resource = "document:readme";

// Avoid
const subject = "alice";
const resource = "readme";
```

### 2. Batch Writes

```javascript
// Good - single request
await write({
  relationships: [
    { resource: "doc:1", relation: "viewer", subject: "user:alice" },
    { resource: "doc:1", relation: "editor", subject: "user:bob" },
  ],
});

// Avoid - multiple requests
await write({ relationships: [{ resource: "doc:1", relation: "viewer", subject: "user:alice" }] });
await write({ relationships: [{ resource: "doc:1", relation: "editor", subject: "user:bob" }] });
```

### 3. Leverage Caching

Identical permission checks are cached automatically. Structure your checks to maximize cache hits.

### 4. Use Trace for Debugging

Use the trace endpoint to understand why a check returned a particular decision.

### 5. Handle Errors Gracefully

Always check status codes and implement proper error handling. Fail closed (deny access) on errors.

## Additional Resources

- **[Quick Start Guide](../docs/guides/quickstart.md)** - Get started with InferaDB
- **[Authentication Guide](../docs/security/authentication.md)** - JWT authentication details
- **[Configuration Guide](../docs/guides/configuration.md)** - Server configuration
- **[IPL Language Guide](../docs/core/ipl.md)** - Authorization policy language
- **[Deployment Guide](../docs/guides/deployment.md)** - Production deployment
- **[GitHub Repository](https://github.com/inferadb/server)** - Source code and issues

## Support

- **Documentation**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/inferadb/server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/inferadb/server/discussions)

---

**Ready to explore?**

- [Open REST API Explorer (Swagger UI)](./swagger-ui.html)
- [Open gRPC API Explorer Guide](./grpc-explorer.html)
