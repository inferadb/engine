# Infera Observe - Observability Layer

Centralized observability for InferaDB with OpenTelemetry tracing, Prometheus metrics, and structured logging.

## Table of Contents

- [Authentication Metrics](#authentication-metrics)
- [JWKS Cache Metrics](#jwks-cache-metrics)
- [OAuth Metrics](#oauth-metrics)
- [Example Prometheus Queries](#example-prometheus-queries)
- [Example Grafana Dashboards](#example-grafana-dashboards)
- [Audit Logging](#audit-logging)
- [OpenTelemetry Tracing](#opentelemetry-tracing)

## Authentication Metrics

Authentication metrics track authentication attempts, successes, failures, and performance.

### Metrics

| Metric Name | Type | Labels | Description |
|------------|------|--------|-------------|
| `inferadb_auth_attempts_total` | Counter | `method`, `tenant_id` | Total number of authentication attempts |
| `inferadb_auth_success_total` | Counter | `method`, `tenant_id` | Total number of successful authentications |
| `inferadb_auth_failure_total` | Counter | `method`, `error_type`, `tenant_id` | Total number of failed authentications |
| `inferadb_auth_duration_seconds` | Histogram | `method`, `tenant_id` | Duration of authentication operations in seconds |
| `inferadb_jwt_signature_verifications_total` | Counter | `algorithm`, `result` | Total number of JWT signature verifications |
| `inferadb_jwt_validation_errors_total` | Counter | `error_type` | Total number of JWT validation errors |

### Label Values

- **method**: `tenant_jwt`, `oauth_jwt`, `internal_jwt`
- **error_type**: `invalid_format`, `expired`, `not_yet_valid`, `invalid_signature`, `invalid_issuer`, `invalid_audience`, `missing_claim`, `unsupported_algorithm`, `jwks_error`
- **algorithm**: `EdDSA`, `RS256`
- **result**: `success`, `failure`

### Example Queries

#### Authentication Success Rate by Tenant

```promql
# Success rate over last 5 minutes
sum(rate(inferadb_auth_success_total[5m])) by (tenant_id)
/
(sum(rate(inferadb_auth_success_total[5m])) by (tenant_id) + sum(rate(inferadb_auth_failure_total[5m])) by (tenant_id))
* 100
```

#### Authentication Latency p99 by Method

```promql
# p99 latency in milliseconds
histogram_quantile(0.99,
  sum(rate(inferadb_auth_duration_seconds_bucket[5m])) by (method, le)
) * 1000
```

#### Failed Authentications by Error Type

```promql
# Failed auths per second by error type
sum(rate(inferadb_auth_failure_total[5m])) by (error_type)
```

#### Total Authentication Throughput

```promql
# Authentications per second (all methods)
sum(rate(inferadb_auth_attempts_total[5m]))
```

## JWKS Cache Metrics

JWKS cache metrics track public key caching performance and freshness.

### Metrics

| Metric Name | Type | Labels | Description |
|------------|------|--------|-------------|
| `inferadb_jwks_cache_hits_total` | Counter | `tenant_id` | Total number of JWKS cache hits |
| `inferadb_jwks_cache_misses_total` | Counter | `tenant_id` | Total number of JWKS cache misses |
| `inferadb_jwks_refresh_total` | Counter | `tenant_id`, `result` | Total number of JWKS refresh operations |
| `inferadb_jwks_refresh_errors_total` | Counter | `tenant_id` | Total number of JWKS refresh errors |
| `inferadb_jwks_fetch_duration_seconds` | Histogram | `tenant_id` | Duration of JWKS fetch operations |
| `inferadb_jwks_stale_served_total` | Counter | `tenant_id` | Number of times stale JWKS was served |

### Example Queries

#### JWKS Cache Hit Rate

```promql
# Cache hit rate over last 5 minutes
sum(rate(inferadb_jwks_cache_hits_total[5m]))
/
(sum(rate(inferadb_jwks_cache_hits_total[5m])) + sum(rate(inferadb_jwks_cache_misses_total[5m])))
* 100
```

#### JWKS Fetch Errors

```promql
# JWKS fetch errors per second
sum(rate(inferadb_jwks_refresh_errors_total[5m])) by (tenant_id)
```

#### Stale JWKS Served Rate

```promql
# Times per second stale JWKS was served (stale-while-revalidate pattern)
sum(rate(inferadb_jwks_stale_served_total[5m])) by (tenant_id)
```

## OAuth Metrics

OAuth metrics track OAuth 2.0 JWT validation and token introspection.

### Metrics

| Metric Name | Type | Labels | Description |
|------------|------|--------|-------------|
| `inferadb_oauth_jwt_validations_total` | Counter | `issuer`, `result` | Total number of OAuth JWT validations |
| `inferadb_oauth_introspections_total` | Counter | `result` | Total number of token introspections |
| `inferadb_oauth_introspection_cache_hits_total` | Counter | | Total number of introspection cache hits |
| `inferadb_oauth_introspection_cache_misses_total` | Counter | | Total number of introspection cache misses |
| `inferadb_oauth_introspection_duration_seconds` | Histogram | | Duration of token introspection operations |
| `inferadb_oidc_discovery_total` | Counter | `issuer`, `result` | Total number of OIDC discovery operations |

### Example Queries

#### OAuth Validation Success Rate by Issuer

```promql
# OAuth validation success rate by issuer
sum(rate(inferadb_oauth_jwt_validations_total{result="success"}[5m])) by (issuer)
/
sum(rate(inferadb_oauth_jwt_validations_total[5m])) by (issuer)
* 100
```

#### Token Introspection Rate

```promql
# Introspections per second
sum(rate(inferadb_oauth_introspections_total[5m]))
```

#### Introspection Cache Hit Rate

```promql
# Introspection cache hit rate
sum(rate(inferadb_oauth_introspection_cache_hits_total[5m]))
/
(sum(rate(inferadb_oauth_introspection_cache_hits_total[5m])) + sum(rate(inferadb_oauth_introspection_cache_misses_total[5m])))
* 100
```

## Example Grafana Dashboards

### Authentication Overview Dashboard

```json
{
  "dashboard": {
    "title": "InferaDB Authentication Overview",
    "panels": [
      {
        "title": "Authentication Success Rate",
        "targets": [
          {
            "expr": "sum(rate(inferadb_auth_success_total[5m])) / (sum(rate(inferadb_auth_success_total[5m])) + sum(rate(inferadb_auth_failure_total[5m]))) * 100"
          }
        ],
        "type": "gauge"
      },
      {
        "title": "Authentication Throughput",
        "targets": [
          {
            "expr": "sum(rate(inferadb_auth_attempts_total[5m]))",
            "legendFormat": "Total"
          },
          {
            "expr": "sum(rate(inferadb_auth_attempts_total[5m])) by (method)",
            "legendFormat": "{{method}}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Authentication Latency (p50, p95, p99)",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, sum(rate(inferadb_auth_duration_seconds_bucket[5m])) by (le)) * 1000",
            "legendFormat": "p50"
          },
          {
            "expr": "histogram_quantile(0.95, sum(rate(inferadb_auth_duration_seconds_bucket[5m])) by (le)) * 1000",
            "legendFormat": "p95"
          },
          {
            "expr": "histogram_quantile(0.99, sum(rate(inferadb_auth_duration_seconds_bucket[5m])) by (le)) * 1000",
            "legendFormat": "p99"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Failed Authentications by Error Type",
        "targets": [
          {
            "expr": "sum(rate(inferadb_auth_failure_total[5m])) by (error_type)",
            "legendFormat": "{{error_type}}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "JWKS Cache Hit Rate",
        "targets": [
          {
            "expr": "sum(rate(inferadb_jwks_cache_hits_total[5m])) / (sum(rate(inferadb_jwks_cache_hits_total[5m])) + sum(rate(inferadb_jwks_cache_misses_total[5m]))) * 100"
          }
        ],
        "type": "gauge"
      }
    ]
  }
}
```

### Security Monitoring Dashboard

```json
{
  "dashboard": {
    "title": "InferaDB Security Monitoring",
    "panels": [
      {
        "title": "Failed Authentication Rate",
        "targets": [
          {
            "expr": "sum(rate(inferadb_auth_failure_total[5m]))",
            "legendFormat": "Total Failures/sec"
          }
        ],
        "type": "graph",
        "alert": {
          "conditions": [
            {
              "evaluator": { "type": "gt", "params": [10] },
              "query": { "model": "sum(rate(inferadb_auth_failure_total[1m]))" }
            }
          ]
        }
      },
      {
        "title": "Authentication Failures by Tenant",
        "targets": [
          {
            "expr": "topk(10, sum(rate(inferadb_auth_failure_total[5m])) by (tenant_id))",
            "legendFormat": "{{tenant_id}}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Invalid Signature Attempts",
        "targets": [
          {
            "expr": "sum(rate(inferadb_jwt_signature_verifications_total{result=\"failure\"}[5m]))",
            "legendFormat": "Invalid Signatures/sec"
          }
        ],
        "type": "graph"
      }
    ]
  }
}
```

## Audit Logging

Audit logs provide a security trail for all authentication events.

### Event Types

#### AuthenticationSuccess

```json
{
  "event_type": "AuthenticationSuccess",
  "tenant_id": "acme",
  "method": "tenant_jwt",
  "timestamp": "2024-01-15T10:30:45Z",
  "ip_address": "192.168.1.100"
}
```

#### AuthenticationFailure

```json
{
  "event_type": "AuthenticationFailure",
  "tenant_id": "unknown",
  "method": "tenant_jwt",
  "error": "Token expired",
  "timestamp": "2024-01-15T10:30:45Z",
  "ip_address": "192.168.1.100"
}
```

#### ScopeViolation

```json
{
  "event_type": "ScopeViolation",
  "tenant_id": "acme",
  "required_scope": "admin",
  "timestamp": "2024-01-15T10:30:45Z"
}
```

#### TenantIsolationViolation

```json
{
  "event_type": "TenantIsolationViolation",
  "tenant_id": "acme",
  "attempted_tenant": "bigcorp",
  "timestamp": "2024-01-15T10:30:45Z"
}
```

### Log Levels

- **INFO**: Successful authentications
- **WARN**: Failed authentications, scope violations, tenant isolation violations

### Querying Audit Logs

Audit logs are structured JSON and can be queried using log aggregation tools:

```bash
# Find all failed authentications in the last hour
jq 'select(.event_type == "AuthenticationFailure" and .timestamp > "2024-01-15T09:00:00Z")'

# Find all authentication attempts from specific IP
jq 'select(.ip_address == "192.168.1.100")'

# Count failures by error type
jq 'select(.event_type == "AuthenticationFailure") | .error' | sort | uniq -c
```

## OpenTelemetry Tracing

Authentication spans are exported to OpenTelemetry with semantic conventions.

### Semantic Conventions

| Attribute | Description | Example |
|-----------|-------------|---------|
| `auth.method` | Authentication method | `tenant_jwt`, `oauth_jwt`, `internal_jwt` |
| `auth.tenant_id` | Tenant identifier | `acme` |
| `auth.scopes` | Comma-separated scopes | `read,write` |
| `auth.result` | Authentication result | `success`, `failure` |
| `auth.error_type` | Error type (if failed) | `expired`, `invalid_signature` |

### Configuration

```rust
use infera_observe::TracingConfig;

let config = TracingConfig {
    service_name: "inferadb".to_string(),
    otlp_endpoint: Some("http://localhost:4317".to_string()),
    sample_rate: 1.0,
};

infera_observe::init_tracing_with_config(config)?;
```

### Sampling Strategy

- **Authentication failures**: Always sampled (100%)
- **Authentication successes**: Parent-based sampling (follows parent span decision)

This ensures all security-relevant events are captured while managing trace volume.

## Usage Examples

### Initializing Observability

```rust
use infera_observe;

// Initialize tracing and metrics
infera_observe::init()?;
```

### Recording Authentication Metrics

```rust
use infera_observe::metrics;

// Record successful authentication
metrics::record_auth_attempt("tenant_jwt", "acme");
metrics::record_auth_success("tenant_jwt", "acme", 0.045);

// Record failed authentication
metrics::record_auth_attempt("tenant_jwt", "unknown");
metrics::record_auth_failure("tenant_jwt", "expired", "unknown", 0.012);
metrics::record_jwt_validation_error("expired");
```

### Creating Authentication Spans

```rust
use infera_observe::span_utils;

let span = span_utils::auth_span("tenant_jwt", Some("acme"));
let _guard = span.enter();

// Authentication logic here

span_utils::record_auth_result(&span, true, 45.0, None);
```

### Logging Audit Events

```rust
use infera_auth::{AuditEvent, log_audit_event};
use chrono::Utc;

log_audit_event(AuditEvent::AuthenticationSuccess {
    tenant_id: "acme".to_string(),
    method: "tenant_jwt".to_string(),
    timestamp: Utc::now(),
    ip_address: Some("192.168.1.100".to_string()),
});
```

## Alerting Rules

### Prometheus Alerting Rules

```yaml
groups:
  - name: authentication_alerts
    rules:
      - alert: HighAuthenticationFailureRate
        expr: sum(rate(inferadb_auth_failure_total[5m])) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate detected"
          description: "Authentication failures are above 10/sec for 5 minutes"

      - alert: JWKSFetchErrors
        expr: sum(rate(inferadb_jwks_refresh_errors_total[5m])) by (tenant_id) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "JWKS fetch errors for tenant {{ $labels.tenant_id }}"
          description: "Unable to fetch JWKS for tenant {{ $labels.tenant_id }}"

      - alert: AuthenticationLatencyHigh
        expr: histogram_quantile(0.99, sum(rate(inferadb_auth_duration_seconds_bucket[5m])) by (le)) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication latency (p99 > 1s)"
          description: "Authentication p99 latency is {{ $value }}s"

      - alert: LowJWKSCacheHitRate
        expr: sum(rate(inferadb_jwks_cache_hits_total[5m])) / (sum(rate(inferadb_jwks_cache_hits_total[5m])) + sum(rate(inferadb_jwks_cache_misses_total[5m]))) < 0.8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Low JWKS cache hit rate (< 80%)"
          description: "JWKS cache hit rate is {{ $value | humanizePercentage }}"
```

## Performance Considerations

### Metrics Cardinality

- **tenant_id** label: Limited by number of tenants (bounded cardinality)
- **method** label: Fixed set of 3 values (`tenant_jwt`, `oauth_jwt`, `internal_jwt`)
- **error_type** label: Fixed set of ~10 error types

Total cardinality is well-bounded and suitable for production use.

### Sampling

- Enable parent-based sampling for high-volume deployments
- Always sample authentication failures for security monitoring
- Adjust sample rate based on request volume

### Storage

- Prometheus: ~1KB per metric series
- OpenTelemetry: ~2KB per trace span
- Logs: ~500 bytes per audit event

Plan storage accordingly for your expected authentication volume.
