# gRPC API Reference

InferaDB provides a high-performance gRPC API for authorization checks, relation expansion, and relationship management. The gRPC API is ideal for production deployments requiring low latency and high throughput.

**🚀 Interactive API Explorer**: Try the gRPC API with [grpcui](./grpc-explorer.html)

**📋 Protocol Buffer Definition**: View the complete [proto file](../crates/infera-api/proto/infera.proto)

## Why gRPC?

- **Performance**: Binary protocol with efficient serialization
- **Streaming**: Support for bidirectional streaming (future feature)
- **Type Safety**: Generated client stubs with strong typing
- **HTTP/2**: Multiplexing, header compression, and connection reuse
- **Cross-Language**: Official support for many languages

## Server Address

```
localhost:8081
```

By default, the gRPC server runs on port 8081 (REST API port + 1). This can be configured via server configuration.

## Protocol Buffers

The complete Protocol Buffer definition is available at [`crates/infera-api/proto/infera.proto`](../crates/infera-api/proto/infera.proto).

## Service Definition

```protobuf
service InferaService {
  rpc Check(CheckRequest) returns (CheckResponse);
  rpc CheckWithTrace(CheckRequest) returns (CheckWithTraceResponse);
  rpc Expand(ExpandRequest) returns (ExpandResponse);
  rpc Write(WriteRequest) returns (WriteResponse);
  rpc Delete(DeleteRequest) returns (DeleteResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

---

## Methods

### Health

Check if the gRPC server is running and healthy.

**Request**: `HealthRequest` (empty)

**Response**: `HealthResponse`

```protobuf
message HealthResponse {
  string status = 1;    // "healthy"
  string service = 2;   // "inferadb"
}
```

**Example (grpcurl)**:

```bash
grpcurl -plaintext localhost:8081 infera.v1.InferaService/Health
```

**Response**:

```json
{
  "status": "healthy",
  "service": "inferadb"
}
```

---

### Check

Check if a subject has a specific permission on a resource.

**Request**: `CheckRequest`

```protobuf
message CheckRequest {
  string subject = 1;      // e.g., "user:alice"
  string resource = 2;     // e.g., "doc:readme"
  string permission = 3;   // e.g., "reader"
  optional string context = 4;  // Optional context JSON
}
```

**Response**: `CheckResponse`

```protobuf
message CheckResponse {
  Decision decision = 1;   // DECISION_ALLOW or DECISION_DENY
}

enum Decision {
  DECISION_UNSPECIFIED = 0;
  DECISION_ALLOW = 1;
  DECISION_DENY = 2;
}
```

**Example (grpcurl)**:

```bash
# Allow case
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "doc:readme",
  "permission": "reader"
}' localhost:8081 infera.v1.InferaService/Check
```

**Response**:

```json
{
  "decision": "DECISION_ALLOW"
}
```

**Example (Go)**:

```go
package main

import (
    "context"
    "log"

    pb "github.com/yourorg/inferadb/api/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    conn, err := grpc.Dial("localhost:8081", grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()

    client := pb.NewInferaServiceClient(conn)

    req := &pb.CheckRequest{
        Subject:    "user:alice",
        Resource:   "doc:readme",
        Permission: "reader",
    }

    resp, err := client.Check(context.Background(), req)
    if err != nil {
        log.Fatalf("Check failed: %v", err)
    }

    if resp.Decision == pb.Decision_DECISION_ALLOW {
        log.Println("Access allowed")
    } else {
        log.Println("Access denied")
    }
}
```

**Example (Python)**:

```python
import grpc
from api.proto import infera_pb2, infera_pb2_grpc

# Create channel and stub
channel = grpc.insecure_channel('localhost:8081')
stub = infera_pb2_grpc.InferaServiceStub(channel)

# Make request
request = infera_pb2.CheckRequest(
    subject='user:alice',
    resource='doc:readme',
    permission='reader'
)

response = stub.Check(request)

if response.decision == infera_pb2.DECISION_ALLOW:
    print("Access allowed")
else:
    print("Access denied")
```

---

### CheckWithTrace

Check permission and return detailed evaluation trace for debugging.

**Request**: `CheckRequest` (same as Check)

**Response**: `CheckWithTraceResponse`

```protobuf
message CheckWithTraceResponse {
  Decision decision = 1;
  DecisionTrace trace = 2;
}

message DecisionTrace {
  Decision decision = 1;
  EvaluationNode root = 2;
  uint64 duration_micros = 3;
  uint64 relationships_read = 4;
  uint64 relations_evaluated = 5;
}

message EvaluationNode {
  NodeType node_type = 1;
  bool result = 2;
  repeated EvaluationNode children = 3;
}
```

**Example (grpcurl)**:

```bash
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "doc:readme",
  "permission": "editor"
}' localhost:8081 infera.v1.InferaService/CheckWithTrace
```

**Response**:

```json
{
  "decision": "DECISION_ALLOW",
  "trace": {
    "decision": "DECISION_ALLOW",
    "root": {
      "nodeType": {
        "union": {}
      },
      "result": true,
      "children": [
        {
          "nodeType": {
            "directCheck": {
              "resource": "doc:readme",
              "relation": "editor",
              "subject": "user:alice"
            }
          },
          "result": true,
          "children": []
        }
      ]
    },
    "durationMicros": "1234",
    "relationshipsRead": "5",
    "relationsEvaluated": "2"
  }
}
```

**Use Cases**:

- Debugging why access was denied
- Understanding complex permission chains
- Performance profiling
- Auditing decision paths

---

### Expand

Expand a relation into a userset tree showing all ways to have that relation.

**Request**: `ExpandRequest`

```protobuf
message ExpandRequest {
  string resource = 1;   // e.g., "doc:readme"
  string relation = 2;   // e.g., "editor"
}
```

**Response**: `ExpandResponse`

```protobuf
message ExpandResponse {
  UsersetTree tree = 1;
}

message UsersetTree {
  UsersetNodeType node_type = 1;
  repeated UsersetTree children = 2;
}

message UsersetNodeType {
  oneof type {
    This this = 1;
    ComputedUsersetRef computed_userset = 2;
    TupleToUsersetRef tuple_to_userset = 3;
    UnionNode union = 4;
    IntersectionNode intersection = 5;
    ExclusionNode exclusion = 6;
    Leaf leaf = 7;
  }
}
```

**Example (grpcurl)**:

```bash
grpcurl -plaintext -d '{
  "resource": "doc:readme",
  "relation": "editor"
}' localhost:8081 infera.v1.InferaService/Expand
```

**Response**:

```json
{
  "tree": {
    "nodeType": {
      "union": {}
    },
    "children": [
      {
        "nodeType": {
          "this": {}
        },
        "children": []
      },
      {
        "nodeType": {
          "computedUserset": {
            "relation": "reader"
          }
        },
        "children": []
      }
    ]
  }
}
```

---

### Write

Write one or more authorization relationships to the store.

**Request**: `WriteRequest`

```protobuf
message WriteRequest {
  repeated Relationship relationships = 1;
}

message Relationship {
  string resource = 1;   // e.g., "doc:readme"
  string relation = 2;   // e.g., "reader"
  string subject = 3;    // e.g., "user:alice"
}
```

**Response**: `WriteResponse`

```protobuf
message WriteResponse {
  string revision = 1;                 // Revision token
  uint64 relationships_written = 2;    // Number of relationships written
}
```

**Example (grpcurl)**:

```bash
grpcurl -plaintext -d '{
  "relationships": [
    {
      "resource": "doc:readme",
      "relation": "reader",
      "subject": "user:alice"
    },
    {
      "resource": "doc:readme",
      "relation": "editor",
      "subject": "user:bob"
    }
  ]
}' localhost:8081 infera.v1.InferaService/Write
```

**Response**:

```json
{
  "revision": "5",
  "relationshipsWritten": "2"
}
```

**Example (Go)**:

```go
req := &pb.WriteRequest{
    Relationships: []*pb.Relationship{
        {
            Resource: "doc:readme",
            Relation: "reader",
            Subject:  "user:alice",
        },
        {
            Resource: "doc:readme",
            Relation: "editor",
            Subject:  "user:bob",
        },
    },
}

resp, err := client.Write(context.Background(), req)
if err != nil {
    log.Fatalf("Write failed: %v", err)
}

log.Printf("Written %d relationships at revision %s", resp.RelationshipsWritten, resp.Revision)
```

---

### Delete

Delete one or more authorization relationships from the store.

**Request**: `DeleteRequest`

```protobuf
message DeleteRequest {
  repeated Relationship relationships = 1;
}
```

**Response**: `DeleteResponse`

```protobuf
message DeleteResponse {
  string revision = 1;                 // Revision token
  uint64 relationships_deleted = 2;    // Number of relationships deleted
}
```

**Example (grpcurl)**:

```bash
grpcurl -plaintext -d '{
  "relationships": [
    {
      "resource": "doc:readme",
      "relation": "reader",
      "subject": "user:alice"
    }
  ]
}' localhost:8081 infera.v1.InferaService/Delete
```

**Response**:

```json
{
  "revision": "6",
  "relationshipsDeleted": "1"
}
```

---

## Error Handling

gRPC uses status codes to indicate errors. InferaDB returns the following codes:

| Code                   | Description                     |
| ---------------------- | ------------------------------- |
| `OK` (0)               | Success                         |
| `INVALID_ARGUMENT` (3) | Invalid request parameters      |
| `NOT_FOUND` (5)        | Resource or relation not found  |
| `INTERNAL` (13)        | Internal server error           |
| `UNAVAILABLE` (14)     | Service temporarily unavailable |

**Example Error (Go)**:

```go
resp, err := client.Check(context.Background(), req)
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        log.Printf("gRPC error: code=%s message=%s", st.Code(), st.Message())
    }
    return
}
```

**Example Error (Python)**:

```python
try:
    response = stub.Check(request)
except grpc.RpcError as e:
    print(f"gRPC error: code={e.code()} message={e.details()}")
```

---

## Client Code Generation

### Go

```bash
# Install protoc and plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate code
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    crates/infera-api/proto/infera.proto
```

### Python

```bash
# Install grpcio-tools
pip install grpcio-tools

# Generate code
python -m grpc_tools.protoc -I. \
    --python_out=. \
    --grpc_python_out=. \
    crates/infera-api/proto/infera.proto
```

### TypeScript/Node.js

```bash
# Install protoc-gen-ts
npm install -g grpc-tools ts-proto

# Generate code
protoc --plugin=protoc-gen-ts=./node_modules/.bin/protoc-gen-ts \
    --ts_out=. \
    crates/infera-api/proto/infera.proto
```

### Rust

Code generation is handled automatically by the `tonic-build` crate in `build.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/infera.proto")?;
    Ok(())
}
```

---

## Complete Example Applications

### Go Client

```go
package main

import (
    "context"
    "log"
    "time"

    pb "github.com/yourorg/inferadb/api/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

type InferaClient struct {
    client pb.InferaServiceClient
}

func NewInferaClient(addr string) (*InferaClient, error) {
    conn, err := grpc.Dial(addr,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithTimeout(5*time.Second),
    )
    if err != nil {
        return nil, err
    }

    return &InferaClient{
        client: pb.NewInferaServiceClient(conn),
    }, nil
}

func (c *InferaClient) Check(ctx context.Context, subject, resource, permission string) (bool, error) {
    req := &pb.CheckRequest{
        Subject:    subject,
        Resource:   resource,
        Permission: permission,
    }

    resp, err := c.client.Check(ctx, req)
    if err != nil {
        return false, err
    }

    return resp.Decision == pb.Decision_DECISION_ALLOW, nil
}

func (c *InferaClient) WriteTuples(ctx context.Context, tuples []*pb.Tuple) (string, error) {
    req := &pb.WriteRequest{Tuples: tuples}
    resp, err := c.client.Write(ctx, req)
    if err != nil {
        return "", err
    }
    return resp.Revision, nil
}

func main() {
    client, err := NewInferaClient("localhost:8081")
    if err != nil {
        log.Fatalf("Failed to create client: %v", err)
    }

    ctx := context.Background()

    // Write tuples
    tuples := []*pb.Tuple{
        {Object: "doc:readme", Relation: "reader", User: "user:alice"},
        {Object: "doc:readme", Relation: "editor", User: "user:bob"},
    }

    revision, err := client.WriteTuples(ctx, tuples)
    if err != nil {
        log.Fatalf("Write failed: %v", err)
    }
    log.Printf("Written tuples at revision %s", revision)

    // Check permission
    allowed, err := client.Check(ctx, "user:alice", "doc:readme", "reader")
    if err != nil {
        log.Fatalf("Check failed: %v", err)
    }

    if allowed {
        log.Println("Access allowed")
    } else {
        log.Println("Access denied")
    }
}
```

### Python Client

```python
import grpc
from api.proto import infera_pb2, infera_pb2_grpc

class InferaClient:
    def __init__(self, addr: str):
        self.channel = grpc.insecure_channel(addr)
        self.stub = infera_pb2_grpc.InferaServiceStub(self.channel)

    def check(self, subject: str, resource: str, permission: str) -> bool:
        request = infera_pb2.CheckRequest(
            subject=subject,
            resource=resource,
            permission=permission
        )
        response = self.stub.Check(request)
        return response.decision == infera_pb2.DECISION_ALLOW

    def write_tuples(self, tuples: list) -> str:
        request = infera_pb2.WriteRequest(tuples=tuples)
        response = self.stub.Write(request)
        return response.revision

    def close(self):
        self.channel.close()

# Usage
client = InferaClient('localhost:8081')

# Write tuples
tuples = [
    infera_pb2.Tuple(object='doc:readme', relation='reader', user='user:alice'),
    infera_pb2.Tuple(object='doc:readme', relation='editor', user='user:bob'),
]
revision = client.write_tuples(tuples)
print(f"Written tuples at revision {revision}")

# Check permission
allowed = client.check('user:alice', 'doc:readme', 'reader')
if allowed:
    print("Access allowed")
else:
    print("Access denied")

client.close()
```

---

## Performance Characteristics

**Latency** (p99):

- `Health`: <1ms
- `Check` (cached): <0.5ms
- `Check` (uncached, simple): <2ms
- `Check` (uncached, complex): <10ms
- `CheckWithTrace`: <5ms (+ trace overhead)
- `Expand`: <25ms
- `Write`: <3ms
- `Delete`: <3ms

**Throughput**:

- Sustained: 50k-200k requests/second per core
- Peak: 500k+ requests/second with connection pooling

**Connection Pooling**:

- gRPC reuses HTTP/2 connections
- Recommended: 1-5 connections per client
- Each connection multiplexes requests

---

## Best Practices

### 1. Connection Pooling

Reuse gRPC channels across requests:

```go
// Good - single channel
conn, _ := grpc.Dial("localhost:8081", opts...)
client := pb.NewInferaServiceClient(conn)
// Reuse client for all requests

// Avoid - new connection per request
for range 1000 {
    conn, _ := grpc.Dial("localhost:8081", opts...)
    client := pb.NewInferaServiceClient(conn)
    client.Check(ctx, req)
    conn.Close() // Wasteful!
}
```

### 2. Context Timeouts

Always use timeouts to prevent hanging requests:

```go
ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
defer cancel()

resp, err := client.Check(ctx, req)
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        log.Println("Request timed out")
    }
}
```

### 3. Batch Writes

Write multiple tuples in a single request:

```go
// Good - batch write
tuples := make([]*pb.Tuple, 100)
// ... populate tuples
client.Write(ctx, &pb.WriteRequest{Tuples: tuples})

// Avoid - individual writes
for _, tuple := range tuples {
    client.Write(ctx, &pb.WriteRequest{Tuples: []*pb.Tuple{tuple}})
}
```

### 4. Error Handling

Check gRPC status codes for proper error handling:

```go
resp, err := client.Check(ctx, req)
if err != nil {
    st, ok := status.FromError(err)
    if !ok {
        return fmt.Errorf("non-gRPC error: %w", err)
    }

    switch st.Code() {
    case codes.InvalidArgument:
        return fmt.Errorf("invalid request: %s", st.Message())
    case codes.Unavailable:
        // Retry with backoff
        return retryWithBackoff(func() error {
            _, err := client.Check(ctx, req)
            return err
        })
    default:
        return fmt.Errorf("gRPC error: %w", err)
    }
}
```

### 5. Use CheckWithTrace for Debugging

Enable tracing during development:

```go
resp, err := client.CheckWithTrace(ctx, req)
if err != nil {
    log.Fatalf("Check failed: %v", err)
}

log.Printf("Decision: %v", resp.Decision)
log.Printf("Trace: %+v", resp.Trace)
log.Printf("Duration: %dμs", resp.Trace.DurationMicros)
log.Printf("Tuples read: %d", resp.Trace.TuplesRead)
```

---

## Testing with grpcurl

[grpcurl](https://github.com/fullstorydev/grpcurl) is a command-line tool for interacting with gRPC servers.

### Installation

```bash
# macOS
brew install grpcurl

# Linux
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Windows
scoop install grpcurl
```

### List Services

```bash
grpcurl -plaintext localhost:8081 list
```

### List Methods

```bash
grpcurl -plaintext localhost:8081 list infera.v1.InferaService
```

### Describe Method

```bash
grpcurl -plaintext localhost:8081 describe infera.v1.InferaService.Check
```

### Make Request

```bash
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "doc:readme",
  "permission": "reader"
}' localhost:8081 infera.v1.InferaService/Check
```

---

## Comparison: gRPC vs REST

| Feature         | gRPC               | REST            |
| --------------- | ------------------ | --------------- |
| Protocol        | HTTP/2 + Protobuf  | HTTP/1.1 + JSON |
| Latency         | ~2ms (p99)         | ~5ms (p99)      |
| Throughput      | 200k RPS           | 100k RPS        |
| Payload Size    | Smaller (binary)   | Larger (text)   |
| Type Safety     | Strong (generated) | Weak (manual)   |
| Streaming       | Yes (future)       | Limited (SSE)   |
| Browser Support | Limited            | Full            |
| Debugging       | grpcurl, tools     | curl, browser   |

**When to use gRPC**:

- High-throughput production deployments
- Service-to-service communication
- Low-latency requirements
- Strong typing needed

**When to use REST**:

- Browser-based applications
- Simple integration requirements
- Human-readable debugging
- Wide client support

---

## TLS/SSL Configuration

**Note**: TLS is not yet implemented. For production deployments, use TLS:

```go
// Future: TLS configuration
creds, err := credentials.NewClientTLSFromFile("cert.pem", "")
conn, err := grpc.Dial("inferadb.example.com:443", grpc.WithTransportCredentials(creds))
```

---

## Next Steps

- See [REST API Reference](api-rest.md) for HTTP/JSON interface
- See [IPL Language Guide](ipl-language.md) for schema definition
- See [Architecture Overview](architecture.md) for system design
- See [Quick Start Guide](quickstart.md) for complete examples
