# Metrics

InferaDB exports Prometheus-compatible metrics at the `/metrics` endpoint for comprehensive performance monitoring and alerting.

## Overview

All metrics follow Prometheus naming conventions and are exposed in OpenMetrics format. Metrics are updated in real-time and can be scraped by Prometheus, Grafana Cloud, Datadog, or any OpenMetrics-compatible monitoring system.

## Metrics Endpoint

Access metrics via HTTP:

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

# HELP inferadb_engine_cache_hit_rate Current cache hit rate as a percentage
# TYPE inferadb_engine_cache_hit_rate gauge
inferadb_engine_cache_hit_rate 85.3
```

## Available Metrics

### Authentication Metrics

InferaDB tracks comprehensive authentication metrics for monitoring security and performance.

| Metric                                       | Type      | Labels                              | Description                                 |
| -------------------------------------------- | --------- | ----------------------------------- | ------------------------------------------- |
| `inferadb_engine_auth_attempts_total`               | Counter   | `method`, `tenant_id`               | Total number of authentication attempts     |
| `inferadb_engine_auth_success_total`                | Counter   | `method`, `tenant_id`               | Total number of successful authentications  |
| `inferadb_engine_auth_failure_total`                | Counter   | `method`, `error_type`, `tenant_id` | Total number of failed authentications      |
| `inferadb_engine_auth_duration_seconds`             | Histogram | `method`, `tenant_id`               | Duration of authentication operations       |
| `inferadb_jwt_signature_verifications_total` | Counter   | `algorithm`, `result`               | Total number of JWT signature verifications |
| `inferadb_jwt_validation_errors_total`       | Counter   | `error_type`                        | Total number of JWT validation errors       |

**Label Values**:

- **method**: `tenant_jwt`, `oauth_jwt`, `internal_jwt`
- **error_type**: `invalid_format`, `expired`, `not_yet_valid`, `invalid_signature`, `invalid_issuer`, `invalid_audience`, `missing_claim`, `unsupported_algorithm`, `jwks_error`
- **algorithm**: `EdDSA`, `RS256`

**Example PromQL Queries**:

```promql
# Authentication success rate
sum(rate(inferadb_engine_auth_success_total[5m])) / sum(rate(inferadb_engine_auth_attempts_total[5m])) * 100

# Authentication failures by error type
sum(rate(inferadb_engine_auth_failure_total[5m])) by (error_type)

# p99 authentication latency
histogram_quantile(0.99, sum(rate(inferadb_engine_auth_duration_seconds_bucket[5m])) by (le))
```

### JWKS Cache Metrics

| Metric                                 | Type      | Labels                | Description                             |
| -------------------------------------- | --------- | --------------------- | --------------------------------------- |
| `inferadb_jwks_cache_hits_total`       | Counter   | `tenant_id`           | Total number of JWKS cache hits         |
| `inferadb_jwks_cache_misses_total`     | Counter   | `tenant_id`           | Total number of JWKS cache misses       |
| `inferadb_jwks_refresh_total`          | Counter   | `tenant_id`, `result` | Total number of JWKS refresh operations |
| `inferadb_jwks_refresh_errors_total`   | Counter   | `tenant_id`           | Total number of JWKS refresh errors     |
| `inferadb_jwks_fetch_duration_seconds` | Histogram | `tenant_id`           | Duration of JWKS fetch operations       |
| `inferadb_jwks_stale_served_total`     | Counter   | `tenant_id`           | Number of times stale JWKS was served   |

**Example PromQL Queries**:

```promql
# JWKS cache hit rate
sum(rate(inferadb_jwks_cache_hits_total[5m])) / (sum(rate(inferadb_jwks_cache_hits_total[5m])) + sum(rate(inferadb_jwks_cache_misses_total[5m]))) * 100

# JWKS fetch errors by tenant
sum(rate(inferadb_jwks_refresh_errors_total[5m])) by (tenant_id)
```

### OAuth Metrics

| Metric                                            | Type      | Labels             | Description                                |
| ------------------------------------------------- | --------- | ------------------ | ------------------------------------------ |
| `inferadb_oauth_jwt_validations_total`            | Counter   | `issuer`, `result` | Total number of OAuth JWT validations      |
| `inferadb_oauth_introspections_total`             | Counter   | `result`           | Total number of token introspections       |
| `inferadb_oauth_introspection_cache_hits_total`   | Counter   |                    | Total number of introspection cache hits   |
| `inferadb_oauth_introspection_cache_misses_total` | Counter   |                    | Total number of introspection cache misses |
| `inferadb_oauth_introspection_duration_seconds`   | Histogram |                    | Duration of token introspection operations |
| `inferadb_oidc_discovery_total`                   | Counter   | `issuer`, `result` | Total number of OIDC discovery operations  |

**Example PromQL Queries**:

```promql
# OAuth validation success rate by issuer
sum(rate(inferadb_oauth_jwt_validations_total{result="success"}[5m])) by (issuer) / sum(rate(inferadb_oauth_jwt_validations_total[5m])) by (issuer) * 100

# Token introspection rate
sum(rate(inferadb_oauth_introspections_total[5m]))
```

### Authorization Check Metrics

| Metric                            | Type      | Description                                      |
| --------------------------------- | --------- | ------------------------------------------------ |
| `inferadb_checks_total`           | Counter   | Total number of authorization checks             |
| `inferadb_checks_allowed_total`   | Counter   | Number of checks resulting in Allow              |
| `inferadb_checks_denied_total`    | Counter   | Number of checks resulting in Deny               |
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

### Cache Metrics

| Metric                        | Type    | Description                        |
| ----------------------------- | ------- | ---------------------------------- |
| `inferadb_engine_cache_hits_total`   | Counter | Total number of cache hits         |
| `inferadb_engine_cache_misses_total` | Counter | Total number of cache misses       |
| `inferadb_engine_cache_entries`      | Gauge   | Current number of entries in cache |
| `inferadb_engine_cache_hit_rate`     | Gauge   | Current cache hit rate (0-100%)    |

**Example PromQL Queries**:

```promql
# Cache hit rate
inferadb_engine_cache_hit_rate

# Cache hit rate (calculated)
sum(rate(inferadb_engine_cache_hits_total[5m])) / (sum(rate(inferadb_engine_cache_hits_total[5m])) + sum(rate(inferadb_engine_cache_misses_total[5m]))) * 100

# Cache usage
inferadb_engine_cache_entries
```

### Storage Metrics

| Metric                                    | Type      | Description                              |
| ----------------------------------------- | --------- | ---------------------------------------- |
| `inferadb_storage_reads_total`            | Counter   | Total number of storage read operations  |
| `inferadb_storage_writes_total`           | Counter   | Total number of storage write operations |
| `inferadb_storage_read_duration_seconds`  | Histogram | Duration of storage read operations      |
| `inferadb_storage_write_duration_seconds` | Histogram | Duration of storage write operations     |
| `inferadb_storage_tuples_total`           | Gauge     | Total number of tuples in storage        |
| `inferadb_storage_revision`               | Gauge     | Current storage revision number          |

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

### WASM Metrics

| Metric                            | Type      | Description                             |
| --------------------------------- | --------- | --------------------------------------- |
| `inferadb_engine_wasm_invocations_total` | Counter   | Total number of WASM module invocations |
| `inferadb_engine_wasm_errors_total`      | Counter   | Total number of WASM execution errors   |
| `inferadb_engine_wasm_duration_seconds`  | Histogram | Duration of WASM module executions      |
| `inferadb_engine_wasm_fuel_consumed`     | Histogram | Amount of fuel consumed by WASM         |

**Example PromQL Queries**:

```promql
# WASM invocation rate
rate(inferadb_engine_wasm_invocations_total[5m])

# WASM error rate
rate(inferadb_engine_wasm_errors_total[5m])

# p99 WASM execution time
histogram_quantile(0.99, rate(inferadb_engine_wasm_duration_seconds_bucket[5m]))
```

### Evaluation Metrics

| Metric                                | Type      | Description                            |
| ------------------------------------- | --------- | -------------------------------------- |
| `inferadb_evaluations_total`          | Counter   | Total number of relation evaluations   |
| `inferadb_evaluation_depth`           | Histogram | Depth of relation evaluation trees     |
| `inferadb_evaluation_branches`        | Histogram | Number of branches evaluated per check |
| `inferadb_parallel_evaluations_total` | Counter   | Total number of parallel evaluations   |

**Example PromQL Queries**:

```promql
# Evaluation rate
rate(inferadb_evaluations_total[5m])

# Average evaluation depth
avg(rate(inferadb_evaluation_depth_sum[5m]) / rate(inferadb_evaluation_depth_count[5m]))

# p99 evaluation depth (deeper = slower)
histogram_quantile(0.99, rate(inferadb_evaluation_depth_bucket[5m]))
```

### Query Optimization Metrics

| Metric                          | Type      | Description                                   |
| ------------------------------- | --------- | --------------------------------------------- |
| `inferadb_optimizations_total`  | Counter   | Total number of query optimizations performed |
| `inferadb_query_cost_estimated` | Histogram | Estimated cost of queries                     |

### Replication Metrics

InferaDB tracks comprehensive replication metrics for monitoring multi-region deployments.

| Metric                                           | Type      | Description                                           |
| ------------------------------------------------ | --------- | ----------------------------------------------------- |
| `inferadb_engine_replication_changes_total`             | Counter   | Total number of changes replicated to remote regions  |
| `inferadb_engine_replication_failures_total`            | Counter   | Total number of replication failures                  |
| `inferadb_engine_replication_conflicts_total`           | Counter   | Total number of replication conflicts detected        |
| `inferadb_engine_replication_conflicts_resolved_local`  | Counter   | Number of conflicts resolved by keeping local change  |
| `inferadb_engine_replication_conflicts_resolved_remote` | Counter   | Number of conflicts resolved by keeping remote change |
| `inferadb_engine_replication_lag_milliseconds`          | Gauge     | Current replication lag in milliseconds               |
| `inferadb_engine_replication_targets_connected`         | Gauge     | Number of replication targets currently connected     |
| `inferadb_engine_replication_targets_total`             | Gauge     | Total number of configured replication targets        |
| `inferadb_engine_replication_batch_size`                | Histogram | Distribution of replication batch sizes               |
| `inferadb_engine_replication_duration_seconds`          | Histogram | Duration of replication operations in seconds         |

**Example PromQL Queries**:

```promql
# Replication lag
inferadb_engine_replication_lag_milliseconds

# Replication throughput (changes per second)
rate(inferadb_engine_replication_changes_total[5m])

# Replication failure rate
rate(inferadb_engine_replication_failures_total[5m])

# Conflict rate (conflicts per second)
rate(inferadb_engine_replication_conflicts_total[5m])

# Conflict resolution distribution
sum(rate(inferadb_engine_replication_conflicts_resolved_local[5m])) / sum(rate(inferadb_engine_replication_conflicts_total[5m])) * 100

# Target health (percentage of connected targets)
inferadb_engine_replication_targets_connected / inferadb_engine_replication_targets_total * 100

# Average batch size
avg(rate(inferadb_engine_replication_batch_size_sum[5m]) / rate(inferadb_engine_replication_batch_size_count[5m]))

# p99 replication duration
histogram_quantile(0.99, rate(inferadb_engine_replication_duration_seconds_bucket[5m]))
```

**Recommended Alerts**:

```yaml
# Alert when replication lag exceeds 100ms
- alert: HighReplicationLag
  expr: inferadb_engine_replication_lag_milliseconds > 100
  for: 5m
  annotations:
    summary: "High replication lag ({{ $value }}ms)"

# Alert when target health drops below 100%
- alert: ReplicationTargetUnhealthy
  expr: (inferadb_engine_replication_targets_connected / inferadb_engine_replication_targets_total) < 1
  for: 2m
  annotations:
    summary: "Replication target unhealthy"

# Alert on high failure rate
- alert: HighReplicationFailureRate
  expr: rate(inferadb_engine_replication_failures_total[5m]) > 0.01
  for: 5m
  annotations:
    summary: "High replication failure rate"

# Alert on high conflict rate
- alert: HighConflictRate
  expr: rate(inferadb_engine_replication_conflicts_total[5m]) / rate(inferadb_engine_replication_changes_total[5m]) > 0.01
  for: 10m
  annotations:
    summary: "High conflict rate (>1% of changes)"
```

For detailed replication documentation, see [Multi-Region Replication](../replication.md).

### Audit Logging Metrics

InferaDB tracks audit logging metrics for monitoring compliance and security event coverage.

| Metric                                | Type    | Labels       | Description                                  |
| ------------------------------------- | ------- | ------------ | -------------------------------------------- |
| `inferadb_audit_events_total`         | Counter | `event_type` | Total number of audit events logged          |
| `inferadb_audit_events_sampled_total` | Counter | `event_type` | Total number of audit events sampled/dropped |
| `inferadb_audit_events_errors_total`  | Counter | `error_type` | Total number of audit logging errors         |

**Event Type Labels**:

- `authorization_check`
- `relationship_write`
- `relationship_delete`
- `resource_list`
- `subject_list`
- `expand`
- `simulation`

**Example PromQL Queries**:

```promql
# Audit event rate by type
sum(rate(inferadb_audit_events_total[5m])) by (event_type)

# Audit sampling rate (percentage of events dropped)
sum(rate(inferadb_audit_events_sampled_total[5m])) / (sum(rate(inferadb_audit_events_total[5m])) + sum(rate(inferadb_audit_events_sampled_total[5m]))) * 100

# Audit error rate
rate(inferadb_audit_events_errors_total[5m])
```

For comprehensive audit logging documentation, see [Audit Logging](auditing.md).

### API Metrics

| Metric                                            | Type      | Description                                  |
| ------------------------------------------------- | --------- | -------------------------------------------- |
| `inferadb_engine_api_requests_total{endpoint,method}`    | Counter   | Total API requests by endpoint and method    |
| `inferadb_engine_api_errors_total{endpoint,status}`      | Counter   | Total API errors by endpoint and status code |
| `inferadb_engine_api_request_duration_seconds{endpoint}` | Histogram | API request duration by endpoint             |
| `inferadb_engine_api_active_connections`                 | Gauge     | Number of currently active connections       |

**Example PromQL Queries**:

```promql
# Request rate by endpoint
rate(inferadb_engine_api_requests_total[5m])

# Error rate
rate(inferadb_engine_api_errors_total[5m])

# Error rate percentage
sum(rate(inferadb_engine_api_errors_total[5m])) / sum(rate(inferadb_engine_api_requests_total[5m])) * 100

# p99 API latency
histogram_quantile(0.99, rate(inferadb_engine_api_request_duration_seconds_bucket[5m]))

# Active connections
inferadb_engine_api_active_connections
```

### System Metrics

| Metric                                | Type  | Description                  |
| ------------------------------------- | ----- | ---------------------------- |
| `inferadb_build_info{version,commit}` | Gauge | Build information (always 1) |
| `inferadb_uptime_seconds`             | Gauge | Time since server started    |

**Example PromQL Queries**:

```promql
# Uptime
inferadb_uptime_seconds

# Uptime in hours
inferadb_uptime_seconds / 3600
```

## Next Steps

- [Distributed Tracing](tracing.md) - OpenTelemetry tracing setup
- [Structured Logging](logging.md) - Configure logging and log formats
- [Audit Logging](auditing.md) - Comprehensive audit trail for compliance
- [Observability Overview](README.md) - Complete observability guide
