# Observability

InferaDB provides comprehensive observability through metrics, tracing, and structured logging. This allows you to monitor performance, debug issues, and understand system behavior in production.

## Overview

InferaDB's observability stack includes:

- **Metrics**: Prometheus-compatible metrics for monitoring
- **Tracing**: OpenTelemetry distributed tracing for request flow
- **Logging**: Structured logging with contextual information

## Metrics

InferaDB exports Prometheus-compatible metrics at the `/metrics` endpoint.

### Metrics Endpoint

```bash
curl http://localhost:8080/metrics
```

**Output** (Prometheus format):

```prometheus
# HELP inferadb_checks_total Total number of authorization checks performed
# TYPE inferadb_checks_total counter
inferadb_checks_total 12453

# HELP inferadb_check_duration_seconds Duration of authorization checks in seconds
# TYPE inferadb_check_duration_seconds histogram
inferadb_check_duration_seconds_bucket{le="0.001"} 9234
inferadb_check_duration_seconds_bucket{le="0.005"} 11892
inferadb_check_duration_seconds_bucket{le="0.01"} 12234
inferadb_check_duration_seconds_bucket{le="0.05"} 12401
inferadb_check_duration_seconds_bucket{le="0.1"} 12450
inferadb_check_duration_seconds_bucket{le="+Inf"} 12453
inferadb_check_duration_seconds_sum 8.234
inferadb_check_duration_seconds_count 12453

# HELP inferadb_cache_hit_rate Current cache hit rate as a percentage
# TYPE inferadb_cache_hit_rate gauge
inferadb_cache_hit_rate 85.3
```

### Available Metrics

#### Authentication Metrics

InferaDB tracks comprehensive authentication metrics for monitoring security and performance.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `inferadb_auth_attempts_total` | Counter | `method`, `tenant_id` | Total number of authentication attempts |
| `inferadb_auth_success_total` | Counter | `method`, `tenant_id` | Total number of successful authentications |
| `inferadb_auth_failure_total` | Counter | `method`, `error_type`, `tenant_id` | Total number of failed authentications |
| `inferadb_auth_duration_seconds` | Histogram | `method`, `tenant_id` | Duration of authentication operations |
| `inferadb_jwt_signature_verifications_total` | Counter | `algorithm`, `result` | Total number of JWT signature verifications |
| `inferadb_jwt_validation_errors_total` | Counter | `error_type` | Total number of JWT validation errors |

**Label Values**:
- **method**: `tenant_jwt`, `oauth_jwt`, `internal_jwt`
- **error_type**: `invalid_format`, `expired`, `not_yet_valid`, `invalid_signature`, `invalid_issuer`, `invalid_audience`, `missing_claim`, `unsupported_algorithm`, `jwks_error`
- **algorithm**: `EdDSA`, `RS256`

**Example PromQL Queries**:

```promql
# Authentication success rate
sum(rate(inferadb_auth_success_total[5m])) / sum(rate(inferadb_auth_attempts_total[5m])) * 100

# Authentication failures by error type
sum(rate(inferadb_auth_failure_total[5m])) by (error_type)

# p99 authentication latency
histogram_quantile(0.99, sum(rate(inferadb_auth_duration_seconds_bucket[5m])) by (le))
```

#### JWKS Cache Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `inferadb_jwks_cache_hits_total` | Counter | `tenant_id` | Total number of JWKS cache hits |
| `inferadb_jwks_cache_misses_total` | Counter | `tenant_id` | Total number of JWKS cache misses |
| `inferadb_jwks_refresh_total` | Counter | `tenant_id`, `result` | Total number of JWKS refresh operations |
| `inferadb_jwks_refresh_errors_total` | Counter | `tenant_id` | Total number of JWKS refresh errors |
| `inferadb_jwks_fetch_duration_seconds` | Histogram | `tenant_id` | Duration of JWKS fetch operations |
| `inferadb_jwks_stale_served_total` | Counter | `tenant_id` | Number of times stale JWKS was served |

**Example PromQL Queries**:

```promql
# JWKS cache hit rate
sum(rate(inferadb_jwks_cache_hits_total[5m])) / (sum(rate(inferadb_jwks_cache_hits_total[5m])) + sum(rate(inferadb_jwks_cache_misses_total[5m]))) * 100

# JWKS fetch errors by tenant
sum(rate(inferadb_jwks_refresh_errors_total[5m])) by (tenant_id)
```

#### OAuth Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `inferadb_oauth_jwt_validations_total` | Counter | `issuer`, `result` | Total number of OAuth JWT validations |
| `inferadb_oauth_introspections_total` | Counter | `result` | Total number of token introspections |
| `inferadb_oauth_introspection_cache_hits_total` | Counter | | Total number of introspection cache hits |
| `inferadb_oauth_introspection_cache_misses_total` | Counter | | Total number of introspection cache misses |
| `inferadb_oauth_introspection_duration_seconds` | Histogram | | Duration of token introspection operations |
| `inferadb_oidc_discovery_total` | Counter | `issuer`, `result` | Total number of OIDC discovery operations |

**Example PromQL Queries**:

```promql
# OAuth validation success rate by issuer
sum(rate(inferadb_oauth_jwt_validations_total{result="success"}[5m])) by (issuer) / sum(rate(inferadb_oauth_jwt_validations_total[5m])) by (issuer) * 100

# Token introspection rate
sum(rate(inferadb_oauth_introspections_total[5m]))
```

For comprehensive authentication metrics documentation, see [infera-observe/README.md](../crates/infera-observe/README.md).

#### Authorization Check Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `inferadb_checks_total` | Counter | Total number of authorization checks |
| `inferadb_checks_allowed_total` | Counter | Number of checks resulting in Allow |
| `inferadb_checks_denied_total` | Counter | Number of checks resulting in Deny |
| `inferadb_check_duration_seconds` | Histogram | Duration of authorization checks (p50, p90, p99) |

**Example PromQL Queries**:

```promql
# Check rate (requests per second)
rate(inferadb_checks_total[5m])

# Allow/Deny ratio
sum(rate(inferadb_checks_allowed_total[5m])) / sum(rate(inferadb_checks_total[5m]))

# p99 latency
histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m]))

# p50 latency
histogram_quantile(0.50, rate(inferadb_check_duration_seconds_bucket[5m]))
```

#### Cache Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `inferadb_cache_hits_total` | Counter | Total number of cache hits |
| `inferadb_cache_misses_total` | Counter | Total number of cache misses |
| `inferadb_cache_entries` | Gauge | Current number of entries in cache |
| `inferadb_cache_hit_rate` | Gauge | Current cache hit rate (0-100%) |

**Example PromQL Queries**:

```promql
# Cache hit rate
inferadb_cache_hit_rate

# Cache hit rate (calculated)
sum(rate(inferadb_cache_hits_total[5m])) / (sum(rate(inferadb_cache_hits_total[5m])) + sum(rate(inferadb_cache_misses_total[5m]))) * 100

# Cache usage
inferadb_cache_entries
```

#### Storage Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `inferadb_storage_reads_total` | Counter | Total number of storage read operations |
| `inferadb_storage_writes_total` | Counter | Total number of storage write operations |
| `inferadb_storage_read_duration_seconds` | Histogram | Duration of storage read operations |
| `inferadb_storage_write_duration_seconds` | Histogram | Duration of storage write operations |
| `inferadb_storage_tuples_total` | Gauge | Total number of tuples in storage |
| `inferadb_storage_revision` | Gauge | Current storage revision number |

**Example PromQL Queries**:

```promql
# Storage read rate
rate(inferadb_storage_reads_total[5m])

# Storage write rate
rate(inferadb_storage_writes_total[5m])

# p99 read latency
histogram_quantile(0.99, rate(inferadb_storage_read_duration_seconds_bucket[5m]))

# Tuple growth rate
rate(inferadb_storage_tuples_total[1h])
```

#### WASM Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `inferadb_wasm_invocations_total` | Counter | Total number of WASM module invocations |
| `inferadb_wasm_errors_total` | Counter | Total number of WASM execution errors |
| `inferadb_wasm_duration_seconds` | Histogram | Duration of WASM module executions |
| `inferadb_wasm_fuel_consumed` | Histogram | Amount of fuel consumed by WASM |

**Example PromQL Queries**:

```promql
# WASM invocation rate
rate(inferadb_wasm_invocations_total[5m])

# WASM error rate
rate(inferadb_wasm_errors_total[5m])

# p99 WASM execution time
histogram_quantile(0.99, rate(inferadb_wasm_duration_seconds_bucket[5m]))
```

#### Evaluation Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `inferadb_evaluations_total` | Counter | Total number of relation evaluations |
| `inferadb_evaluation_depth` | Histogram | Depth of relation evaluation trees |
| `inferadb_evaluation_branches` | Histogram | Number of branches evaluated per check |

**Example PromQL Queries**:

```promql
# Evaluation rate
rate(inferadb_evaluations_total[5m])

# Average evaluation depth
avg(rate(inferadb_evaluation_depth_sum[5m]) / rate(inferadb_evaluation_depth_count[5m]))

# p99 evaluation depth (deeper = slower)
histogram_quantile(0.99, rate(inferadb_evaluation_depth_bucket[5m]))
```

#### Query Optimization Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `inferadb_optimizations_total` | Counter | Total number of query optimizations performed |
| `inferadb_query_cost_estimated` | Histogram | Estimated cost of queries |
| `inferadb_parallel_evaluations_total` | Counter | Total number of parallel evaluations |

#### API Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `inferadb_api_requests_total{endpoint,method}` | Counter | Total API requests by endpoint and method |
| `inferadb_api_errors_total{endpoint,status}` | Counter | Total API errors by endpoint and status code |
| `inferadb_api_request_duration_seconds{endpoint}` | Histogram | API request duration by endpoint |
| `inferadb_api_active_connections` | Gauge | Number of currently active connections |

**Example PromQL Queries**:

```promql
# Request rate by endpoint
rate(inferadb_api_requests_total[5m])

# Error rate
rate(inferadb_api_errors_total[5m])

# Error rate percentage
sum(rate(inferadb_api_errors_total[5m])) / sum(rate(inferadb_api_requests_total[5m])) * 100

# p99 API latency
histogram_quantile(0.99, rate(inferadb_api_request_duration_seconds_bucket[5m]))

# Active connections
inferadb_api_active_connections
```

#### System Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `inferadb_build_info{version,commit}` | Gauge | Build information (always 1) |
| `inferadb_uptime_seconds` | Gauge | Time since server started |

**Example PromQL Queries**:

```promql
# Uptime
inferadb_uptime_seconds

# Uptime in hours
inferadb_uptime_seconds / 3600
```

---

## Distributed Tracing

InferaDB supports OpenTelemetry distributed tracing for end-to-end request visualization.

### Configuration

**Environment Variables**:

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

### Trace Context

Every authorization check creates a trace with the following structure:

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

**Span Attributes**:

- `inferadb.subject`: Subject of the check
- `inferadb.resource`: Resource being accessed
- `inferadb.permission`: Permission being checked
- `inferadb.decision`: Final decision (allow/deny)
- `inferadb.cache_hit`: Whether cache was hit
- `inferadb.tuples_read`: Number of tuples read
- `inferadb.relations_evaluated`: Number of relations evaluated

### Jaeger Integration

**Start Jaeger**:

```bash
docker run -d --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 4317:4317 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest
```

**Configure InferaDB**:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export INFERA__OBSERVABILITY__TRACING_ENABLED=true
inferadb
```

**View Traces**: http://localhost:16686

### Trace Example

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

---

## Audit Logging

InferaDB provides comprehensive audit logging for all authentication events to support security monitoring, compliance, and incident response.

### Event Types

#### AuthenticationSuccess

Logged at **INFO** level when authentication succeeds:

```json
{
  "event_type": "AuthenticationSuccess",
  "tenant_id": "acme",
  "method": "tenant_jwt",
  "timestamp": "2025-01-15T10:30:45Z",
  "ip_address": "192.168.1.100"
}
```

#### AuthenticationFailure

Logged at **WARN** level when authentication fails:

```json
{
  "event_type": "AuthenticationFailure",
  "tenant_id": "unknown",
  "method": "tenant_jwt",
  "error": "Token expired",
  "timestamp": "2025-01-15T10:30:45Z",
  "ip_address": "192.168.1.100"
}
```

#### ScopeViolation

Logged at **WARN** level when a request lacks required scope:

```json
{
  "event_type": "ScopeViolation",
  "tenant_id": "acme",
  "required_scope": "admin",
  "timestamp": "2025-01-15T10:30:45Z"
}
```

#### TenantIsolationViolation

Logged at **WARN** level when cross-tenant access is attempted:

```json
{
  "event_type": "TenantIsolationViolation",
  "tenant_id": "acme",
  "attempted_tenant": "bigcorp",
  "timestamp": "2025-01-15T10:30:45Z"
}
```

### Querying Audit Logs

Audit logs are structured JSON and can be queried using log aggregation tools:

```bash
# Find all failed authentications in the last hour
jq 'select(.event_type == "AuthenticationFailure" and .timestamp > "2025-01-15T09:00:00Z")'

# Find all authentication attempts from specific IP
jq 'select(.ip_address == "192.168.1.100")'

# Count failures by error type
jq 'select(.event_type == "AuthenticationFailure") | .error' | sort | uniq -c
```

For comprehensive audit logging documentation, see [infera-observe/README.md](../crates/infera-observe/README.md#audit-logging).

---

## Structured Logging

InferaDB uses structured logging with contextual fields for debugging and auditing.

### Log Levels

Set log level via configuration:

```bash
export INFERA__OBSERVABILITY__LOG_LEVEL=info
# Or via RUST_LOG
export RUST_LOG=infera=debug,infera_api=info
```

**Log Levels**:
- `error`: Errors only
- `warn`: Warnings and errors
- `info`: Informational, warnings, and errors (default)
- `debug`: Detailed debugging information
- `trace`: Very verbose tracing

### Log Formats

**Development** (pretty, human-readable):

```
2025-01-15T10:30:45.123Z  INFO infera_api::handlers: Authorization check
  subject: user:alice
  resource: doc:readme
  permission: viewer
  decision: allow
  duration_ms: 3.2
```

**Production** (JSON, machine-parseable):

```json
{
  "timestamp": "2025-01-15T10:30:45.123Z",
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
    "id": "abc123"
  }
}
```

### Contextual Logging

InferaDB automatically adds contextual information to logs:

```rust
// Example: Check handler logs
info!(
    subject = %request.subject,
    resource = %request.resource,
    permission = %request.permission,
    decision = ?decision,
    duration_ms = duration.as_secs_f64() * 1000.0,
    "Authorization check completed"
);
```

**Log Entry**:

```
INFO Authorization check completed subject=user:alice resource=doc:readme permission=viewer decision=Allow duration_ms=3.2
```

### Log Filtering

Filter logs by module:

```bash
# Show all logs
export RUST_LOG=debug

# Show only infera-core logs at debug level
export RUST_LOG=infera_core=debug

# Multiple modules
export RUST_LOG=infera_core=debug,infera_api=info,infera_store=warn

# Filter by span
export RUST_LOG=infera[check]=trace
```

---

## Monitoring Setup

### Prometheus Setup

**prometheus.yml**:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'inferadb'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

**Start Prometheus**:

```bash
docker run -d --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

**Access**: http://localhost:9090

### Grafana Dashboard

**Sample Dashboard JSON**:

```json
{
  "dashboard": {
    "title": "InferaDB Overview",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(inferadb_checks_total[5m])"
          }
        ]
      },
      {
        "title": "p99 Latency",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Cache Hit Rate",
        "targets": [
          {
            "expr": "inferadb_cache_hit_rate"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "sum(rate(inferadb_api_errors_total[5m])) / sum(rate(inferadb_api_requests_total[5m])) * 100"
          }
        ]
      }
    ]
  }
}
```

### Alert Rules

**alerts.yml**:

```yaml
groups:
  - name: inferadb
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: sum(rate(inferadb_api_errors_total[5m])) / sum(rate(inferadb_api_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }}% (threshold: 5%)"

      # High latency
      - alert: HighLatency
        expr: histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High p99 latency detected"
          description: "p99 latency is {{ $value }}s (threshold: 100ms)"

      # Low cache hit rate
      - alert: LowCacheHitRate
        expr: inferadb_cache_hit_rate < 50
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "Low cache hit rate"
          description: "Cache hit rate is {{ $value }}% (threshold: 50%)"

      # High storage latency
      - alert: HighStorageLatency
        expr: histogram_quantile(0.99, rate(inferadb_storage_read_duration_seconds_bucket[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High storage read latency"
          description: "p99 storage read latency is {{ $value }}s (threshold: 50ms)"
```

---

## Performance Monitoring

### Key Performance Indicators (KPIs)

1. **Request Rate**: `rate(inferadb_checks_total[5m])`
2. **p99 Latency**: `histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m]))`
3. **Error Rate**: `sum(rate(inferadb_api_errors_total[5m])) / sum(rate(inferadb_api_requests_total[5m]))`
4. **Cache Hit Rate**: `inferadb_cache_hit_rate`
5. **Storage Throughput**: `rate(inferadb_storage_reads_total[5m]) + rate(inferadb_storage_writes_total[5m])`

### Performance Thresholds

**Latency**:
- p50 < 5ms (good)
- p90 < 10ms (acceptable)
- p99 < 50ms (threshold)
- p99 > 100ms (investigate)

**Cache Hit Rate**:
- \> 90%: Excellent
- 70-90%: Good
- 50-70%: Acceptable
- < 50%: Poor (investigate)

**Error Rate**:
- < 0.1%: Excellent
- 0.1-1%: Acceptable
- 1-5%: Warning
- \> 5%: Critical (alert)

---

## Debugging

### Enable Debug Logging

```bash
export RUST_LOG=debug
inferadb
```

### Trace Specific Requests

Add trace ID to logs:

```bash
# Set log level to trace for specific module
export RUST_LOG=infera_core::evaluator=trace
```

### View Decision Traces

Use `CheckWithTrace` API for detailed evaluation traces:

```bash
grpcurl -plaintext -d '{
  "subject": "user:alice",
  "resource": "doc:readme",
  "permission": "viewer"
}' localhost:8081 infera.v1.InferaService/CheckWithTrace
```

---

## Best Practices

### 1. Monitor Key Metrics

Focus on:
- Request rate
- Latency (p50, p90, p99)
- Error rate
- Cache hit rate

### 2. Set Alerts

Alert on:
- High error rate (> 5%)
- High latency (p99 > 100ms)
- Low cache hit rate (< 50%)

### 3. Use Structured Logging

Include contextual information in logs:

```rust
info!(
    user_id = %user.id,
    resource_id = %resource.id,
    decision = ?decision,
    "Check completed"
);
```

### 4. Sample Traces in Production

Use sampling to reduce overhead:

```bash
export OTEL_TRACES_SAMPLER=traceidratio
export OTEL_TRACES_SAMPLER_ARG=0.1  # 10% sampling
```

### 5. Aggregate Logs

Send logs to centralized logging:
- Elasticsearch + Kibana
- Grafana Loki
- AWS CloudWatch
- Datadog

---

## Next Steps

- [Configuration](configuration.md) - Configure observability settings
- [API Reference](api-rest.md) - Monitor API endpoints
- [Caching System](caching.md) - Monitor cache performance
- [Storage Backends](storage-backends.md) - Monitor storage metrics
