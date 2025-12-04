# Structured Logging

InferaDB uses structured logging with contextual fields for debugging, monitoring, and auditing. Logs are emitted via the `tracing` framework and can be formatted as human-readable text or machine-parseable JSON.

## Overview

InferaDB's logging system provides:

- **Structured Fields**: Rich contextual information in every log entry
- **Multiple Formats**: Human-readable (compact) or JSON for log aggregation
- **Span Correlation**: Automatic correlation with distributed traces
- **Module Filtering**: Fine-grained control over log verbosity
- **Performance**: Minimal overhead with async logging

## Configuration

### Log Level

Set log level via environment variables:

```bash
# Via InferaDB configuration
export INFERADB__OBSERVABILITY__LOG_LEVEL=info

# Or via RUST_LOG (more granular)
export RUST_LOG=infera=debug,infera_api=info
```

**Available Log Levels**:

- `error`: Critical errors only
- `warn`: Warnings and errors
- `info`: Informational messages, warnings, and errors (default)
- `debug`: Detailed debugging information
- `trace`: Very verbose tracing (includes all function calls)

### Log Format

Configure output format:

```bash
# Compact format (human-readable, for development)
export INFERADB__OBSERVABILITY__LOG_FORMAT=compact

# JSON format (machine-parseable, for production)
export INFERADB__OBSERVABILITY__LOG_FORMAT=json
```

### Full Configuration Example

```yaml
observability:
  log_level: info
  log_format: json
  log_spans: true
  include_location: true # Include file:line in logs
  include_target: true # Include module path
  include_thread_id: false # Include thread ID
```

## Log Formats

### Compact Format (Development)

Human-readable format for local development:

```
2025-01-15T10:30:45.123Z  INFO infera_api::handlers: Authorization check
  subject: user:alice
  resource: doc:readme
  permission: viewer
  decision: allow
  duration_ms: 3.2
```

**Features**:

- Color-coded log levels (when terminal supports it)
- Indented structured fields
- Compact timestamps
- Module paths shown

### JSON Format (Production)

Machine-parseable JSON for log aggregation systems:

```json
{
  "timestamp": "2025-01-15T10:30:45.123456Z",
  "level": "INFO",
  "target": "infera_api::handlers",
  "message": "Authorization check",
  "fields": {
    "subject": "user:alice",
    "resource": "doc:readme",
    "permission": "viewer",
    "decision": "allow",
    "duration_ms": 3.2
  },
  "span": {
    "name": "check",
    "id": "abc123",
    "parent_id": "xyz789"
  },
  "trace_id": "80f198ee56343ba864fe8b2a57d3eff7",
  "location": {
    "file": "crates/infera-api/src/handlers/check.rs",
    "line": 142
  }
}
```

**Features**:

- ISO 8601 timestamps with microsecond precision
- Trace and span IDs for correlation
- Source code location
- Structured fields for easy querying

## Contextual Logging

InferaDB automatically adds contextual information to logs based on the operation:

### Authorization Check Logs

```rust
info!(
    subject = %request.subject,
    resource = %request.resource,
    permission = %request.permission,
    decision = ?decision,
    duration_ms = duration.as_secs_f64() * 1000.0,
    cache_hit = cache_hit,
    "Authorization check completed"
);
```

**Output**:

```
INFO Authorization check completed subject=user:alice resource=doc:readme permission=viewer decision=Allow duration_ms=3.2 cache_hit=false
```

### Storage Operation Logs

```
DEBUG Storage read operation tuples_read=15 duration_ms=1.8 revision=42
```

### Authentication Logs

```
INFO Authentication successful method=tenant_jwt tenant_id=acme user=alice duration_ms=12.5
```

## Log Filtering

### By Module

Filter logs by Rust module path:

```bash
# Show all logs
export RUST_LOG=debug

# Show only infera-core logs at debug level
export RUST_LOG=infera_core=debug

# Multiple modules with different levels
export RUST_LOG=infera_core=debug,infera_api=info,infera_store=warn

# All modules at info, but infera_core at trace
export RUST_LOG=info,infera_core=trace
```

### By Span

Filter logs within specific spans:

```bash
# Trace logs only within "check" spans
export RUST_LOG=infera[check]=trace

# Debug logs in authorization spans
export RUST_LOG=infera[authorization]=debug
```

### By Target Pattern

Use regex patterns for flexible filtering:

```bash
# All API-related modules
export RUST_LOG=infera_api

# All modules containing "cache"
export RUST_LOG=cache=debug

# Multiple patterns
export RUST_LOG="infera_api,infera_cache=debug"
```

## Log Targets

InferaDB uses specific log targets for different subsystems:

| Target                    | Description                         | Default Level |
| ------------------------- | ----------------------------------- | ------------- |
| `infera_api`              | REST and gRPC API requests          | INFO          |
| `infera_core::evaluator`  | Authorization evaluation engine     | INFO          |
| `infera_store`            | Storage backend operations          | INFO          |
| `infera_auth`             | Authentication and JWT validation   | INFO          |
| `infera_cache`            | Cache operations (hits/misses)      | DEBUG         |
| `inferadb_audit`          | Audit logging (JSON events)         | INFO          |
| `infera_observe::metrics` | Metrics recording                   | DEBUG         |
| `infera_observe::tracing` | Distributed tracing                 | DEBUG         |
| `infera_core::optimizer`  | Query optimization                  | DEBUG         |
| `infera_core::parallel`   | Parallel evaluation                 | DEBUG         |
| `infera_replication`      | Multi-region replication            | INFO          |
| `h2`, `hyper`, `tower`    | HTTP/gRPC framework logs (external) | WARN          |
| `foundationdb`            | FoundationDB client logs (external) | WARN          |

## Common Logging Patterns

### Development

Maximum verbosity for debugging:

```bash
export RUST_LOG=debug
export INFERADB__OBSERVABILITY__LOG_FORMAT=compact
export INFERADB__OBSERVABILITY__LOG_SPANS=true
```

### Production

Structured JSON with info level:

```bash
export RUST_LOG=info,h2=warn,hyper=warn
export INFERADB__OBSERVABILITY__LOG_FORMAT=json
export INFERADB__OBSERVABILITY__LOG_SPANS=false
```

### Debugging Specific Issue

Enable trace for specific component:

```bash
# Debugging slow authorization checks
export RUST_LOG=info,infera_core::evaluator=trace

# Debugging cache issues
export RUST_LOG=info,infera_cache=trace

# Debugging authentication failures
export RUST_LOG=info,infera_auth=debug

# Debugging storage performance
export RUST_LOG=info,infera_store=debug
```

### Performance Testing

Minimal logging for accurate benchmarks:

```bash
export RUST_LOG=warn
export INFERADB__OBSERVABILITY__LOG_SPANS=false
```

## Log Aggregation

### Elasticsearch + Kibana

Ship JSON logs to Elasticsearch using Filebeat:

**filebeat.yml**:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/inferadb/*.json
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "inferadb-%{+yyyy.MM.dd}"

setup.ilm.enabled: false
setup.template.name: "inferadb"
setup.template.pattern: "inferadb-*"
```

**Kibana Queries**:

```
# Find all failed authorization checks
level: ERROR AND fields.decision: deny

# Find slow requests (> 100ms)
fields.duration_ms: >100

# Find authentication failures
target: "infera_auth" AND level: WARN
```

### Grafana Loki

Ship logs to Loki using Promtail:

**promtail-config.yml**:

```yaml
server:
  http_listen_port: 9080

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: inferadb
    static_configs:
      - targets:
          - localhost
        labels:
          job: inferadb
          __path__: /var/log/inferadb/*.json
    pipeline_stages:
      - json:
          expressions:
            level: level
            target: target
            trace_id: trace_id
      - labels:
          level:
          target:
```

**LogQL Queries**:

```logql
# Find errors
{job="inferadb"} |= `"level":"ERROR"`

# Find slow authorization checks
{job="inferadb"} | json | duration_ms > 100

# Find by trace ID
{job="inferadb"} | json | trace_id = "80f198ee56343ba864fe8b2a57d3eff7"
```

### Datadog Logs

Send logs to Datadog:

**datadog.yaml**:

```yaml
logs_enabled: true

logs_config:
  logs_dd_url: intake.logs.datadoghq.com:10516

  container_collect_all: false

  logs:
    - type: file
      path: /var/log/inferadb/*.json
      service: inferadb
      source: rust
      sourcecategory: inferadb
      tags:
        - env:production
```

### AWS CloudWatch

Use the CloudWatch agent:

**cloudwatch-config.json**:

```json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/inferadb/*.json",
            "log_group_name": "/inferadb/application",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
```

## Debugging

### Enable Debug Logging

```bash
export RUST_LOG=debug
inferadb
```

### Trace Specific Operation

Enable trace logging for detailed flow:

```bash
# Trace authorization evaluation
export RUST_LOG=infera_core::evaluator=trace

# Output shows every step:
TRACE Evaluating relation relation=viewer resource=doc:readme
TRACE Checking direct relationships count=3
TRACE Evaluating computed userset relation=editor
TRACE Union evaluation branches=2 results=[true, false]
TRACE Final decision decision=Allow duration_ms=3.2
```

### View Decision Traces

Use the `CheckWithTrace` API for authorization decision debugging:

```bash
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "doc:readme",
  "permission": "viewer"
}' localhost:8081 infera.v1.InferaService/CheckWithTrace
```

**Response includes full evaluation tree**:

```json
{
  "decision": "ALLOWED",
  "trace": {
    "resource": "doc:readme",
    "permission": "viewer",
    "steps": [
      {
        "relation": "viewer",
        "type": "UNION",
        "children": [
          {
            "relation": "editor",
            "type": "COMPUTED_USERSET",
            "result": "ALLOWED"
          }
        ],
        "result": "ALLOWED"
      }
    ]
  }
}
```

### Correlate Logs with Traces

Every log entry includes trace and span IDs when tracing is enabled:

```json
{
  "timestamp": "2025-01-15T10:30:45.123Z",
  "level": "DEBUG",
  "message": "Evaluating relation",
  "trace_id": "80f198ee56343ba864fe8b2a57d3eff7",
  "span_id": "e457b5a2e4d86bd1"
}
```

Use these IDs to find the corresponding trace in Jaeger/Datadog/etc.

### Debugging Common Issues

**1. Slow Authorization Checks**

```bash
# Enable trace logging for evaluation
export RUST_LOG=info,infera_core::evaluator=debug

# Look for:
# - High relation evaluation depth
# - Many storage reads
# - Cache misses
```

**2. Authentication Failures**

```bash
# Enable debug logging for auth
export RUST_LOG=info,infera_auth=debug

# Look for:
# - JWT validation errors
# - JWKS fetch failures
# - Token expiry
```

**3. Cache Performance**

```bash
# Enable trace logging for cache
export RUST_LOG=info,infera_cache=trace

# Look for:
# - Cache hit/miss patterns
# - Cache key collisions
# - Invalidation frequency
```

**4. Storage Performance**

```bash
# Enable debug logging for storage
export RUST_LOG=info,infera_store=debug

# Look for:
# - High read latency
# - Transaction retries
# - Connection pool exhaustion
```

## Performance Considerations

### Log Level Impact

| Level | Overhead | Logs Generated | Use Case           |
| ----- | -------- | -------------- | ------------------ |
| ERROR | ~0%      | Very few       | Production minimal |
| WARN  | ~0.1%    | Few            | Production         |
| INFO  | ~0.5%    | Moderate       | Production (rec.)  |
| DEBUG | ~2-5%    | Many           | Staging/debugging  |
| TRACE | ~10-20%  | Very many      | Local dev only     |

### Async Logging

InferaDB uses async logging by default:

- Log messages are buffered and written asynchronously
- Minimal impact on request latency
- Flush on process shutdown to prevent log loss

### Sampling

For very high-volume logs, consider sampling:

```rust
// Only log 10% of cache hits
if rand::random::<f64>() < 0.1 {
    debug!("Cache hit");
}
```

## Best Practices

### 1. Use Appropriate Log Levels

```rust
// ERROR: System failures, data corruption
error!("Failed to connect to storage: {}", e);

// WARN: Recoverable issues, degraded performance
warn!("Cache hit rate below 50%: {:.2}%", hit_rate);

// INFO: Important state changes, business events
info!("Authorization check completed");

// DEBUG: Detailed flow, intermediate values
debug!("Evaluating relation: {}", relation);

// TRACE: Very verbose, every function call
trace!("Entering evaluate_union");
```

### 2. Include Contextual Fields

Always add relevant context:

```rust
// Good
info!(
    subject = %subject,
    resource = %resource,
    permission = %permission,
    "Authorization check"
);

// Bad (missing context)
info!("Check completed");
```

### 3. Use JSON in Production

Enable structured logging for log aggregation:

```bash
export INFERADB__OBSERVABILITY__LOG_FORMAT=json
```

### 4. Filter Noisy Logs

Suppress framework logs in production:

```bash
export RUST_LOG=info,h2=warn,hyper=warn,tower=warn
```

### 5. Rotate Log Files

Use logrotate or similar:

```
/var/log/inferadb/*.json {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    missingok
}
```

## Next Steps

- [Distributed Tracing](tracing.md) - Correlate logs with traces
- [Metrics](metrics.md) - Complement logs with metrics
- [Audit Logging](auditing.md) - Compliance and security audit trail
- [Observability Overview](README.md) - Complete observability guide
