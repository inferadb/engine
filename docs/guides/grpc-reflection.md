# gRPC Server Reflection

InferaDB's gRPC server includes support for [gRPC Server Reflection](https://github.com/grpc/grpc/blob/master/doc/server-reflection.md), which allows clients to discover service definitions at runtime without needing the `.proto` files.

## What is gRPC Reflection?

gRPC Server Reflection is a protocol that allows gRPC clients to:

- Discover available services and methods
- Retrieve service definitions dynamically
- Interact with the API without pre-compiled protobuf files

This is particularly useful for:

- **Development and debugging** - Quickly test APIs without client code
- **Interactive exploration** - Use GUI tools like grpcui to browse services
- **Dynamic clients** - Build clients that adapt to API changes
- **Documentation** - Auto-generate API documentation from live services

## Enabling Reflection

Reflection is **enabled by default** in InferaDB's gRPC server. When you start the server, you'll see:

```
INFO gRPC reflection enabled
INFO Starting gRPC server on 0.0.0.0:8081
```

The reflection service is automatically registered alongside the InferaService and is available on the same port (default: 8081).

## Using grpcurl

[grpcurl](https://github.com/fullstorydev/grpcurl) is a command-line tool for interacting with gRPC services.

### Installation

**macOS (via Homebrew):**

```bash
brew install grpcurl
```

**Linux/macOS (via Go):**

```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

**Download Binary:**
Visit <https://github.com/fullstorydev/grpcurl/releases>

### Basic Usage

**List all services:**

```bash
grpcurl -plaintext localhost:8081 list
```

Output:

```
grpc.reflection.v1.ServerReflection
infera.v1.InferaService
```

**List methods for a service:**

```bash
grpcurl -plaintext localhost:8081 list infera.v1.InferaService
```

Output:

```
infera.v1.InferaService.DeleteRelationships
infera.v1.InferaService.Evaluate
infera.v1.InferaService.Expand
infera.v1.InferaService.Health
infera.v1.InferaService.ListRelationships
infera.v1.InferaService.ListResources
infera.v1.InferaService.ListSubjects
infera.v1.InferaService.Watch
infera.v1.InferaService.WriteRelationships
```

**Describe a method:**

```bash
grpcurl -plaintext localhost:8081 describe infera.v1.InferaService.Evaluate
```

Output:

```
infera.v1.InferaService.Evaluate is a method:
rpc Evaluate ( stream .infera.v1.EvaluateRequest ) returns ( stream .infera.v1.EvaluateResponse );
```

**Describe a message type:**

```bash
grpcurl -plaintext localhost:8081 describe infera.v1.EvaluateRequest
```

Output:

```
infera.v1.EvaluateRequest is a message:
message EvaluateRequest {
  string subject = 1;
  string resource = 2;
  string permission = 3;
  optional string context = 4;
  optional bool trace = 5;
}
```

### Example Requests

**Health check:**

```bash
grpcurl -plaintext localhost:8081 infera.v1.InferaService/Health
```

**Write relationships:**

```bash
grpcurl -plaintext \
  -d '{
    "relationships": [
      {
        "resource": "document:readme",
        "relation": "viewer",
        "subject": "user:alice"
      }
    ]
  }' \
  localhost:8081 infera.v1.InferaService/WriteRelationships
```

**Check permission (streaming):**

```bash
grpcurl -plaintext \
  -d @ \
  localhost:8081 infera.v1.InferaService/Evaluate <<EOF
{"subject": "user:alice", "resource": "document:readme", "permission": "viewer"}
EOF
```

**List resources (streaming):**

```bash
grpcurl -plaintext \
  -d '{
    "subject": "user:alice",
    "resource_type": "document",
    "permission": "viewer"
  }' \
  localhost:8081 infera.v1.InferaService/ListResources
```

### Authentication with grpcurl

If authentication is enabled, include JWT tokens in metadata:

```bash
grpcurl -plaintext \
  -H "authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"subject": "user:alice", "resource": "document:readme", "permission": "viewer"}' \
  localhost:8081 infera.v1.InferaService/Evaluate
```

## Using grpcui

[grpcui](https://github.com/fullstorydev/grpcui) is a web-based GUI for interacting with gRPC services.

### Installation

**macOS (via Homebrew):**

```bash
brew install grpcui
```

**Linux/macOS (via Go):**

```bash
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
```

**Download Binary:**
Visit <https://github.com/fullstorydev/grpcui/releases>

### Basic Usage

**Start grpcui:**

```bash
grpcui -plaintext localhost:8081
```

This will:

1. Connect to the gRPC server
2. Use reflection to discover services
3. Start a web server (typically on <http://127.0.0.1:60551>)
4. Open your browser automatically

### Using the GUI

The grpcui interface provides:

1. **Service Explorer** - Browse available services and methods
2. **Method Selector** - Choose which RPC to invoke
3. **Request Editor** - JSON editor for request messages
4. **Invoke Button** - Send the request
5. **Response Viewer** - View responses (including streaming)

### Example Workflow

1. **Start grpcui:**

   ```bash
   grpcui -plaintext localhost:8081
   ```

2. **Select a service:**
   - Choose `infera.v1.InferaService` from the service dropdown

3. **Select a method:**
   - Choose `WriteRelationships` from the method list

4. **Compose request:**

   ```json
   {
     "relationships": [
       {
         "resource": "document:readme",
         "relation": "viewer",
         "subject": "user:alice"
       }
     ]
   }
   ```

5. **Invoke and view response:**
   - Click "Invoke" to send the request
   - View the response with revision and count

6. **Test streaming methods:**
   - Select `Evaluate` (bidirectional streaming)
   - Enter multiple evaluate requests
   - See responses stream back in real-time

### Authentication with grpcui

If authentication is enabled:

```bash
grpcui -plaintext \
  -H "authorization: Bearer YOUR_JWT_TOKEN" \
  localhost:8081
```

Or set metadata in the GUI:

1. Click "Metadata" tab
2. Add header: `authorization: Bearer YOUR_JWT_TOKEN`
3. Invoke requests normally

## TLS/Encrypted Connections

For production deployments with TLS:

**grpcurl:**

```bash
# With system CA certificates
grpcurl localhost:8081 list

# With custom CA certificate
grpcurl -cacert /path/to/ca.crt localhost:8081 list

# Skip verification (development only!)
grpcurl -insecure localhost:8081 list
```

**grpcui:**

```bash
# With system CA certificates
grpcui localhost:8081

# With custom CA certificate
grpcui -cacert /path/to/ca.crt localhost:8081

# Skip verification (development only!)
grpcui -insecure localhost:8081
```

## Troubleshooting

### Connection Refused

**Problem:** `Error invoking method: Failed to dial target host`

**Solution:**

- Verify the gRPC server is running
- Check the port (default: 8081)
- Ensure no firewall is blocking the port

### Reflection Not Available

**Problem:** `Server does not support the reflection API`

**Solution:**

- Verify you're using InferaDB v0.1.0 or later
- Check server logs for `gRPC reflection enabled`
- Ensure you're connecting to the gRPC port (not REST port)

### Authentication Errors

**Problem:** `Unauthenticated` or `Permission denied`

**Solution:**

- Include valid JWT token in Authorization header
- Check token has required scopes (e.g., `inferadb.check`)
- Verify token hasn't expired

### TLS Errors

**Problem:** `x509: certificate signed by unknown authority`

**Solution:**

- Use `-plaintext` for development (no TLS)
- Provide CA certificate with `-cacert`
- Use `-insecure` to skip verification (dev only!)

## Security Considerations

1. **Production Deployment:**
   - Reflection is safe to enable in production
   - Reflection only exposes service definitions, not data
   - Authentication still applies to all RPC calls

2. **Firewall:**
   - Ensure gRPC port is properly firewalled
   - Only expose to authorized networks
   - Use TLS for encrypted communication

3. **Monitoring:**
   - Reflection requests are logged
   - Monitor for unusual reflection usage patterns
   - Use observability tools to track gRPC metrics

## Advanced Usage

### Generate OpenAPI/Swagger Docs

Use reflection to generate API documentation:

```bash
# Export service definition
grpcurl -plaintext localhost:8081 describe infera.v1.InferaService > api.txt

# Or use tools like grpc-gateway to generate OpenAPI specs
```

### Dynamic Client Development

Build clients that adapt to API changes:

```python
import grpc
from grpc_reflection.v1alpha import reflection_pb2
from grpc_reflection.v1alpha import reflection_pb2_grpc

# Connect and discover services
channel = grpc.insecure_channel('localhost:8081')
stub = reflection_pb2_grpc.ServerReflectionStub(channel)

# List services
request = reflection_pb2.ServerReflectionRequest(list_services='')
response = stub.ServerReflectionInfo(iter([request]))
# ... process response
```

### Testing Automation

Integrate reflection into testing pipelines:

```bash
#!/bin/bash
# Verify all expected services are available

SERVICES=$(grpcurl -plaintext localhost:8081 list)

if echo "$SERVICES" | grep -q "infera.v1.InferaService"; then
  echo "✓ InferaService available"
else
  echo "✗ InferaService missing"
  exit 1
fi
```

## Related Documentation

- [gRPC Server Documentation](https://docs.inferadb.com/grpc)
- [Authentication Guide](../security/authentication.md)
- [Deployment Guide](deployment.md)
- [API Reference](https://docs.inferadb.com/api)

## References

- [gRPC Server Reflection Spec](https://github.com/grpc/grpc/blob/master/doc/server-reflection.md)
- [grpcurl Documentation](https://github.com/fullstorydev/grpcurl)
- [grpcui Documentation](https://github.com/fullstorydev/grpcui)
- [tonic-reflection](https://docs.rs/tonic-reflection/)
