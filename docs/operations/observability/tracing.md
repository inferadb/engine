# Distributed Tracing

InferaDB supports OpenTelemetry distributed tracing for end-to-end request visualization, performance debugging, and understanding complex authorization decision flows.

## Overview

Distributed tracing allows you to:

- Visualize the complete flow of authorization requests
- Identify performance bottlenecks in relation evaluation
- Debug complex permission hierarchies
- Understand cache hit/miss patterns
- Track storage access patterns
- Correlate requests across services

## Configuration

### Environment Variables

```bash
# Enable tracing
export INFERA__OBSERVABILITY__TRACING_ENABLED=true

# Configure OTLP endpoint
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

# Set service name
export OTEL_SERVICE_NAME=inferadb

# Set sampling rate (0.0 to 1.0)
export OTEL_TRACES_SAMPLER=always_on  # Sample all traces
export OTEL_TRACES_SAMPLER=traceidratio
export OTEL_TRACES_SAMPLER_ARG=0.1    # Sample 10% of traces
```

### Configuration File

```yaml
observability:
    tracing:
        enabled: true
        exporter:
            otlp:
                endpoint: "http://localhost:4317"
                protocol: grpc
        sampling:
            type: "traceidratio" # or "always_on", "always_off"
            ratio: 0.1 # 10% sampling
        service_name: "inferadb"
```

## Trace Structure

### Authorization Check Trace

Every authorization check creates a trace with the following hierarchical structure:

```
[Span] POST /check
  ├─ [Span] evaluate_check
  │   ├─ [Span] schema_lookup
  │   ├─ [Span] cache_lookup
  │   ├─ [Span] relation_evaluation
  │   │   ├─ [Span] storage_read
  │   │   ├─ [Span] computed_userset
  │   │   └─ [Span] tuple_to_userset
  │   └─ [Span] cache_write
  └─ [Span] serialize_response
```

### Span Attributes

InferaDB enriches traces with contextual attributes:

**Request Attributes**:

- `inferadb.subject`: Subject of the check (e.g., "user:alice")
- `inferadb.resource`: Resource being accessed (e.g., "doc:readme")
- `inferadb.permission`: Permission being checked (e.g., "viewer")
- `inferadb.decision`: Final decision ("allow" or "deny")

**Performance Attributes**:

- `inferadb.cache_hit`: Whether cache was hit (boolean)
- `inferadb.tuples_read`: Number of tuples read from storage
- `inferadb.relations_evaluated`: Number of relations evaluated
- `inferadb.evaluation_depth`: Depth of relation tree evaluation

**Storage Attributes**:

- `inferadb.storage.backend`: Storage backend type ("memory", "foundationdb")
- `inferadb.storage.revision`: Storage revision used for the check

**Authentication Attributes**:

- `inferadb.tenant_id`: Tenant ID (multi-tenant deployments)
- `inferadb.auth.method`: Authentication method used

## Jaeger Integration

Jaeger is the recommended tracing backend for local development and production deployments.

### Quick Start with Jaeger

**1. Start Jaeger**:

```bash
docker run -d --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 4317:4317 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest
```

**2. Configure InferaDB**:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export INFERA__OBSERVABILITY__TRACING_ENABLED=true
inferadb
```

**3. View Traces**: http://localhost:16686

### Jaeger UI Features

- **Search**: Find traces by service, operation, tags, duration
- **Timeline**: Visualize request flow and timing
- **Dependencies**: View service dependency graph
- **Comparison**: Compare traces side-by-side

## Trace Examples

### Example 1: Simple Authorization Check

**Request**:

```bash
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "doc:readme",
    "permission": "viewer"
  }'
```

**Trace** (in Jaeger):

```
inferadb-check [3.2ms]
  subject: user:alice
  resource: doc:readme
  permission: viewer
  decision: allow
  cache_hit: false
  tuples_read: 3
  relations_evaluated: 2

  ├─ schema-lookup [0.1ms]
  ├─ cache-lookup [0.2ms]
  │   cache_key: user:alice/doc:readme/viewer/5
  │   cache_hit: false
  ├─ evaluate-relation [2.5ms]
  │   relation: viewer
  │   ├─ storage-read [1.0ms]
  │   │   tuples_read: 3
  │   └─ computed-userset [1.2ms]
  │       relation: editor
  │       └─ storage-read [0.8ms]
  │           tuples_read: 2
  └─ cache-write [0.3ms]
      ttl_seconds: 300
```

### Example 2: Cache Hit

**Trace with Cache Hit**:

```
inferadb-check [0.5ms]
  subject: user:bob
  resource: doc:readme
  permission: viewer
  decision: allow
  cache_hit: true

  ├─ schema-lookup [0.1ms]
  └─ cache-lookup [0.4ms]
      cache_key: user:bob/doc:readme/viewer/5
      cache_hit: true
      cached_decision: allow
```

### Example 3: Complex Nested Evaluation

**Trace with Deep Relation Tree**:

```
inferadb-check [12.3ms]
  subject: user:alice
  resource: folder:project
  permission: admin
  decision: allow
  cache_hit: false
  relations_evaluated: 7
  evaluation_depth: 4

  ├─ schema-lookup [0.1ms]
  ├─ cache-lookup [0.2ms]
  ├─ evaluate-relation [11.5ms]
  │   relation: admin
  │   ├─ storage-read [1.2ms]
  │   │   tuples_read: 2
  │   ├─ computed-userset [9.8ms]
  │   │   relation: owner
  │   │   ├─ storage-read [0.8ms]
  │   │   └─ tuple-to-userset [8.5ms]
  │   │       resource: org:acme
  │   │       relation: member
  │   │       ├─ storage-read [1.2ms]
  │   │       └─ computed-userset [6.8ms]
  │   │           relation: admin
  │   │           └─ storage-read [1.5ms]
  │   └─ union-evaluation [0.5ms]
  └─ cache-write [0.3ms]
```

## OpenTelemetry Collector

For production deployments, use the OpenTelemetry Collector for advanced routing, filtering, and batching.

### Collector Configuration

**config.yaml**:

```yaml
receivers:
    otlp:
        protocols:
            grpc:
                endpoint: 0.0.0.0:4317
            http:
                endpoint: 0.0.0.0:4318

processors:
    batch:
        timeout: 10s
        send_batch_size: 1024

    filter/drop_health_checks:
        traces:
            span:
                - 'attributes["http.target"] == "/health"'

    attributes:
        actions:
            - key: deployment.environment
              value: production
              action: insert

exporters:
    jaeger:
        endpoint: jaeger:14250
        tls:
            insecure: true

    otlp/datadog:
        endpoint: https://trace.agent.datadoghq.com
        headers:
            DD-API-KEY: ${DD_API_KEY}

service:
    pipelines:
        traces:
            receivers: [otlp]
            processors: [filter/drop_health_checks, batch, attributes]
            exporters: [jaeger, otlp/datadog]
```

**Start Collector**:

```bash
docker run -d --name otel-collector \
  -v $(pwd)/config.yaml:/etc/otel/config.yaml \
  -p 4317:4317 \
  -p 4318:4318 \
  otel/opentelemetry-collector-contrib:latest \
  --config=/etc/otel/config.yaml
```

## Other Backend Integrations

### Datadog APM

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://trace.agent.datadoghq.com
export OTEL_EXPORTER_OTLP_HEADERS="DD-API-KEY=<your-api-key>"
export INFERA__OBSERVABILITY__TRACING_ENABLED=true
```

### New Relic

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.nr-data.net:4317
export OTEL_EXPORTER_OTLP_HEADERS="api-key=<your-license-key>"
export INFERA__OBSERVABILITY__TRACING_ENABLED=true
```

### AWS X-Ray

```bash
# Use OpenTelemetry Collector with AWS X-Ray exporter
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export INFERA__OBSERVABILITY__TRACING_ENABLED=true
```

### Google Cloud Trace

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://cloudtrace.googleapis.com/v2/projects/PROJECT_ID/traces:batchWrite
export INFERA__OBSERVABILITY__TRACING_ENABLED=true
```

## Sampling Strategies

### Always On (Development)

Sample every trace:

```bash
export OTEL_TRACES_SAMPLER=always_on
```

**Use for**: Local development, debugging

### Trace ID Ratio (Production)

Sample a percentage of traces:

```bash
export OTEL_TRACES_SAMPLER=traceidratio
export OTEL_TRACES_SAMPLER_ARG=0.1  # 10% sampling
```

**Use for**: Production environments with high traffic

### Parent-Based (Default)

Respect parent trace sampling decision:

```bash
export OTEL_TRACES_SAMPLER=parentbased_traceidratio
export OTEL_TRACES_SAMPLER_ARG=0.1
```

**Use for**: Multi-service architectures

## Performance Impact

Tracing overhead depends on sampling rate and export method:

| Sampling Rate | Overhead | Use Case                    |
| ------------- | -------- | --------------------------- |
| 100% (always) | ~5-10%   | Development, debugging      |
| 10%           | ~0.5-1%  | Production (high traffic)   |
| 1%            | ~0.1%    | Production (very high load) |
| 0% (disabled) | 0%       | Maximum performance         |

**Recommendations**:

- Development: 100% sampling
- Staging: 100% sampling
- Production (low traffic): 100% sampling
- Production (high traffic): 10% sampling
- Production (very high traffic): 1% sampling

## Debugging with Traces

### Finding Slow Requests

In Jaeger UI:

1. Search by service: "inferadb"
2. Filter by min duration: "100ms"
3. Analyze span waterfall
4. Identify bottlenecks (storage, evaluation depth, cache misses)

### Debugging Permission Denials

1. Search for traces with `decision:deny`
2. Examine evaluation spans to see which relations were checked
3. Look at `tuples_read` to verify data is present
4. Check evaluation depth for complex hierarchies

### Identifying Cache Issues

1. Search for `cache_hit:false` with high duration
2. Compare cache hit vs cache miss traces
3. Analyze cache key patterns
4. Verify TTL settings

## Best Practices

### 1. Use Appropriate Sampling

Don't sample 100% in production unless necessary:

```bash
# Production
export OTEL_TRACES_SAMPLER_ARG=0.1  # 10%

# Development
export OTEL_TRACES_SAMPLER=always_on
```

### 2. Add Custom Attributes

Enrich traces with application context:

```rust
use tracing::info_span;

let span = info_span!(
    "custom_operation",
    custom_field = %custom_value,
    user_type = "premium"
);
```

### 3. Use Trace Context Propagation

Ensure trace IDs propagate across service boundaries:

```rust
// HTTP headers
X-B3-TraceId: 80f198ee56343ba864fe8b2a57d3eff7
X-B3-SpanId: e457b5a2e4d86bd1
X-B3-Sampled: 1
```

### 4. Monitor Trace Export Errors

Watch for trace export failures:

```promql
rate(otel_trace_exporter_errors_total[5m])
```

### 5. Correlate with Logs

Use trace IDs in logs for correlation:

```json
{
    "timestamp": "2025-01-15T10:30:45Z",
    "level": "INFO",
    "message": "Authorization check",
    "trace_id": "80f198ee56343ba864fe8b2a57d3eff7",
    "span_id": "e457b5a2e4d86bd1"
}
```

## Next Steps

- [Structured Logging](logging.md) - Configure logging with trace correlation
- [Metrics](metrics.md) - Complement traces with metrics
- [Audit Logging](auditing.md) - Comprehensive audit trail
- [Observability Overview](README.md) - Complete observability guide
