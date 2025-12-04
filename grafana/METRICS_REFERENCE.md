# InferaDB Metrics Reference

This document provides a comprehensive reference for all Prometheus metrics exposed by InferaDB.

## Table of Contents

- [Authorization Metrics](#authorization-metrics)
- [Query Operation Metrics](#query-operation-metrics)
- [Access Pattern Metrics](#access-pattern-metrics)
- [Condition Evaluation Metrics](#condition-evaluation-metrics)
- [Cache Metrics](#cache-metrics)
- [Storage Metrics](#storage-metrics)
- [WASM Metrics](#wasm-metrics)
- [Evaluation Metrics](#evaluation-metrics)
- [API Metrics](#api-metrics)
- [Authentication Metrics](#authentication-metrics)
- [Replication Metrics](#replication-metrics)
- [System Metrics](#system-metrics)

---

## Authorization Metrics

### `inferadb_checks_total`

**Type**: Counter

**Description**: Total number of authorization checks performed

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_checks_total[5m])
```

### `inferadb_checks_allowed_total`

**Type**: Counter

**Description**: Total number of checks that resulted in Allow

**Labels**: None

**Usage Example**:

```promql
sum(rate(inferadb_checks_allowed_total[5m])) / sum(rate(inferadb_checks_total[5m]))
```

### `inferadb_checks_denied_total`

**Type**: Counter

**Description**: Total number of checks that resulted in Deny

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_checks_denied_total[5m])
```

### `inferadb_check_duration_seconds`

**Type**: Histogram

**Description**: Duration of authorization checks in seconds

**Labels**: None

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m])) * 1000
```

---

## Query Operation Metrics

### `inferadb_query_operations_total`

**Type**: Counter

**Description**: Total number of API operations by query type

**Labels**:

- `operation`: Query operation type (e.g., "Evaluate", "ListResources", "ListSubjects", "Expand", "WriteRelationships", "DeleteRelationships", "Watch", "Simulate")

**Usage Example**:

```promql
sum by (operation) (rate(inferadb_query_operations_total[5m]))
```

### `inferadb_query_operation_duration_seconds`

**Type**: Histogram

**Description**: Duration of API operations by query type in seconds

**Labels**:

- `operation`: Query operation type

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, sum by (operation, le) (rate(inferadb_query_operation_duration_seconds_bucket[5m]))) * 1000
```

---

## Access Pattern Metrics

### `inferadb_resource_checks_total`

**Type**: Counter

**Description**: Total number of authorization checks per resource

**Labels**:

- `resource`: Resource identifier (e.g., "document:readme", "folder:reports")

**Usage Example**:

```promql
topk(10, sum by (resource) (rate(inferadb_resource_checks_total[5m])))
```

**Note**: High cardinality metric - monitor cardinality to avoid Prometheus performance issues.

### `inferadb_subject_checks_total`

**Type**: Counter

**Description**: Total number of authorization checks per subject

**Labels**:

- `subject`: Subject identifier (e.g., "user:alice", "group:engineers")

**Usage Example**:

```promql
topk(10, sum by (subject) (rate(inferadb_subject_checks_total[5m])))
```

**Note**: High cardinality metric - monitor cardinality to avoid Prometheus performance issues.

### `inferadb_permission_checks_total`

**Type**: Counter

**Description**: Total number of authorization checks per permission type

**Labels**:

- `permission`: Permission name (e.g., "viewer", "editor", "admin")

**Usage Example**:

```promql
sum by (permission) (rate(inferadb_permission_checks_total[5m]))
```

### `inferadb_resource_type_checks_total`

**Type**: Counter

**Description**: Total number of authorization checks per resource type

**Labels**:

- `resource_type`: Resource type extracted from resource identifier (e.g., "document", "folder", "organization")

**Usage Example**:

```promql
sum by (resource_type) (rate(inferadb_resource_type_checks_total[5m]))
```

---

## Condition Evaluation Metrics

### `inferadb_condition_evaluations_total`

**Type**: Counter

**Description**: Total number of condition evaluations (WASM, contextual)

**Labels**:

- `condition_type`: Type of condition being evaluated (e.g., "wasm", "contextual", "temporal")

**Usage Example**:

```promql
sum by (condition_type) (rate(inferadb_condition_evaluations_total[5m]))
```

### `inferadb_condition_evaluation_duration_seconds`

**Type**: Histogram

**Description**: Duration of condition evaluations in seconds

**Labels**:

- `condition_type`: Type of condition

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, sum by (condition_type, le) (rate(inferadb_condition_evaluation_duration_seconds_bucket[5m]))) * 1000
```

### `inferadb_condition_evaluation_success_total`

**Type**: Counter

**Description**: Total number of successful condition evaluations

**Labels**:

- `condition_type`: Type of condition

**Usage Example**:

```promql
sum by (condition_type) (rate(inferadb_condition_evaluation_success_total[5m]))
```

### `inferadb_condition_evaluation_failure_total`

**Type**: Counter

**Description**: Total number of failed condition evaluations

**Labels**:

- `condition_type`: Type of condition

**Usage Example**:

```promql
sum by (condition_type) (rate(inferadb_condition_evaluation_failure_total[5m]))
```

---

## Cache Metrics

### `inferadb_cache_hits_total`

**Type**: Counter

**Description**: Total number of cache hits

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_cache_hits_total[5m])
```

### `inferadb_cache_misses_total`

**Type**: Counter

**Description**: Total number of cache misses

**Labels**: None

**Usage Example**:

```promql
sum(rate(inferadb_cache_hits_total[5m])) / (sum(rate(inferadb_cache_hits_total[5m])) + sum(rate(inferadb_cache_misses_total[5m]))) * 100
```

### `inferadb_cache_entries`

**Type**: Gauge

**Description**: Current number of entries in the cache

**Labels**: None

**Usage Example**:

```promql
inferadb_cache_entries
```

### `inferadb_cache_hit_rate`

**Type**: Gauge

**Description**: Current cache hit rate as a percentage

**Labels**: None

**Usage Example**:

```promql
inferadb_cache_hit_rate
```

---

## Storage Metrics

### `inferadb_storage_reads_total`

**Type**: Counter

**Description**: Total number of storage read operations

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_storage_reads_total[5m])
```

### `inferadb_storage_writes_total`

**Type**: Counter

**Description**: Total number of storage write operations

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_storage_writes_total[5m])
```

### `inferadb_storage_read_duration_seconds`

**Type**: Histogram

**Description**: Duration of storage read operations in seconds

**Labels**: None

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, rate(inferadb_storage_read_duration_seconds_bucket[5m])) * 1000
```

### `inferadb_storage_write_duration_seconds`

**Type**: Histogram

**Description**: Duration of storage write operations in seconds

**Labels**: None

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, rate(inferadb_storage_write_duration_seconds_bucket[5m])) * 1000
```

### `inferadb_storage_relationships_total`

**Type**: Gauge

**Description**: Total number of relationships in storage

**Labels**: None

**Usage Example**:

```promql
inferadb_storage_relationships_total
```

### `inferadb_storage_revision`

**Type**: Gauge

**Description**: Current storage revision number

**Labels**: None

**Usage Example**:

```promql
inferadb_storage_revision
```

---

## WASM Metrics

### `inferadb_wasm_invocations_total`

**Type**: Counter

**Description**: Total number of WASM module invocations

**Labels**:

- `module`: WASM module name

**Usage Example**:

```promql
sum by (module) (rate(inferadb_wasm_invocations_total[5m]))
```

### `inferadb_wasm_errors_total`

**Type**: Counter

**Description**: Total number of WASM execution errors

**Labels**:

- `module`: WASM module name

**Usage Example**:

```promql
sum by (module) (rate(inferadb_wasm_errors_total[5m]))
```

### `inferadb_wasm_duration_seconds`

**Type**: Histogram

**Description**: Duration of WASM module executions in seconds

**Labels**:

- `module`: WASM module name

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, sum by (module, le) (rate(inferadb_wasm_duration_seconds_bucket[5m]))) * 1000
```

### `inferadb_wasm_fuel_consumed`

**Type**: Histogram

**Description**: Amount of fuel consumed by WASM executions

**Labels**:

- `module`: WASM module name

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, sum by (module, le) (rate(inferadb_wasm_fuel_consumed_bucket[5m])))
```

---

## Evaluation Metrics

### `inferadb_evaluations_total`

**Type**: Counter

**Description**: Total number of relation evaluations

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_evaluations_total[5m])
```

### `inferadb_evaluation_depth`

**Type**: Histogram

**Description**: Depth of relation evaluation trees

**Labels**: None

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, rate(inferadb_evaluation_depth_bucket[5m]))
```

### `inferadb_evaluation_branches`

**Type**: Histogram

**Description**: Number of branches evaluated per check

**Labels**: None

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, rate(inferadb_evaluation_branches_bucket[5m]))
```

---

## API Metrics

### `inferadb_api_requests_total`

**Type**: Counter

**Description**: Total number of API requests by endpoint and method

**Labels**:

- `endpoint`: API endpoint path
- `method`: HTTP method (GET, POST, etc.)
- `status`: HTTP status code

**Usage Example**:

```promql
sum by (endpoint, method) (rate(inferadb_api_requests_total[5m]))
```

### `inferadb_api_errors_total`

**Type**: Counter

**Description**: Total number of API errors by endpoint and status code

**Labels**:

- `endpoint`: API endpoint path
- `status`: HTTP status code

**Usage Example**:

```promql
sum by (endpoint) (rate(inferadb_api_errors_total{status=~"5.."}[5m]))
```

### `inferadb_api_request_duration_seconds`

**Type**: Histogram

**Description**: Duration of API requests in seconds

**Labels**:

- `endpoint`: API endpoint path
- `method`: HTTP method

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, sum by (endpoint, le) (rate(inferadb_api_request_duration_seconds_bucket[5m]))) * 1000
```

### `inferadb_api_active_connections`

**Type**: Gauge

**Description**: Number of currently active API connections

**Labels**: None

**Usage Example**:

```promql
inferadb_api_active_connections
```

---

## Authentication Metrics

### `inferadb_auth_attempts_total`

**Type**: Counter

**Description**: Total number of authentication attempts

**Labels**:

- `method`: Authentication method (e.g., "tenant_jwt", "oauth_jwt", "internal_jwt")
- `tenant_id`: Tenant identifier

**Usage Example**:

```promql
sum by (method) (rate(inferadb_auth_attempts_total[5m]))
```

### `inferadb_auth_success_total`

**Type**: Counter

**Description**: Total number of successful authentications

**Labels**:

- `method`: Authentication method
- `tenant_id`: Tenant identifier

**Usage Example**:

```promql
sum by (method) (rate(inferadb_auth_success_total[5m]))
```

### `inferadb_auth_failure_total`

**Type**: Counter

**Description**: Total number of failed authentications

**Labels**:

- `method`: Authentication method
- `error_type`: Type of authentication error
- `tenant_id`: Tenant identifier

**Usage Example**:

```promql
sum by (error_type) (rate(inferadb_auth_failure_total[5m]))
```

### `inferadb_auth_duration_seconds`

**Type**: Histogram

**Description**: Duration of authentication operations in seconds

**Labels**:

- `method`: Authentication method
- `tenant_id`: Tenant identifier

**Buckets**: Standard exponential buckets

**Usage Example**:

```promql
histogram_quantile(0.99, sum by (method, le) (rate(inferadb_auth_duration_seconds_bucket[5m]))) * 1000
```

---

## Replication Metrics

### `inferadb_replication_changes_total`

**Type**: Counter

**Description**: Total number of changes replicated to remote regions

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_replication_changes_total[5m])
```

### `inferadb_replication_failures_total`

**Type**: Counter

**Description**: Total number of replication failures

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_replication_failures_total[5m])
```

### `inferadb_replication_conflicts_total`

**Type**: Counter

**Description**: Total number of replication conflicts detected

**Labels**: None

**Usage Example**:

```promql
rate(inferadb_replication_conflicts_total[5m])
```

### `inferadb_replication_lag_milliseconds`

**Type**: Gauge

**Description**: Current replication lag in milliseconds

**Labels**: None

**Usage Example**:

```promql
inferadb_replication_lag_milliseconds
```

### `inferadb_replication_targets_connected`

**Type**: Gauge

**Description**: Number of replication targets currently connected

**Labels**: None

**Usage Example**:

```promql
inferadb_replication_targets_connected
```

### `inferadb_replication_targets_total`

**Type**: Gauge

**Description**: Total number of configured replication targets

**Labels**: None

**Usage Example**:

```promql
inferadb_replication_targets_total
```

---

## System Metrics

### `inferadb_build_info`

**Type**: Gauge

**Description**: Build information (version, commit, etc.)

**Labels**:

- `version`: InferaDB version
- `commit`: Git commit hash

**Value**: Always 1

**Usage Example**:

```promql
inferadb_build_info
```

### `inferadb_uptime_seconds`

**Type**: Gauge

**Description**: Time since server started in seconds

**Labels**: None

**Usage Example**:

```promql
inferadb_uptime_seconds
```

---

## Best Practices

### Cardinality Management

**High Cardinality Metrics**: The following metrics can have high cardinality and should be monitored carefully:

- `inferadb_resource_checks_total` (labeled by resource ID)
- `inferadb_subject_checks_total` (labeled by subject ID)

**Recommendations**:

1. Use `topk()` or `bottomk()` to limit results:

   ```promql
   topk(20, sum by (resource) (rate(inferadb_resource_checks_total[5m])))
   ```

2. Set up recording rules for frequently-used queries:

   ```yaml
   - record: job:inferadb_resource_checks:rate5m
     expr: sum by (resource) (rate(inferadb_resource_checks_total[5m]))
   ```

3. Monitor cardinality with Prometheus:

   ```promql
   count({__name__=~"inferadb_.*"}) by (__name__)
   ```

### Recording Rules

Create recording rules for expensive queries that are used in multiple dashboards:

```yaml
groups:
  - name: inferadb_recording_rules
    interval: 30s
    rules:
      # Query operation rates
      - record: job:inferadb_query_operations:rate5m
        expr: sum by (operation) (rate(inferadb_query_operations_total[5m]))

      # Authorization decision ratio
      - record: job:inferadb_checks:allow_ratio
        expr: sum(rate(inferadb_checks_allowed_total[5m])) / sum(rate(inferadb_checks_total[5m]))

      # Cache hit rate
      - record: job:inferadb_cache:hit_rate
        expr: sum(rate(inferadb_cache_hits_total[5m])) / (sum(rate(inferadb_cache_hits_total[5m])) + sum(rate(inferadb_cache_misses_total[5m])))

      # p99 latency by operation
      - record: job:inferadb_query_operation:p99_latency_ms
        expr: histogram_quantile(0.99, sum by (operation, le) (rate(inferadb_query_operation_duration_seconds_bucket[5m]))) * 1000
```

### Alert Examples

Example alert rules based on these metrics:

```yaml
groups:
  - name: inferadb_alerts
    rules:
      # High error rate
      - alert: HighAuthorizationErrorRate
        expr: sum(rate(inferadb_api_errors_total{status=~"5.."}[5m])) / sum(rate(inferadb_checks_total[5m])) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authorization error rate"
          description: "Authorization error rate is {{ $value | humanizePercentage }}"

      # Slow queries
      - alert: SlowQueryPerformance
        expr: histogram_quantile(0.99, sum by (operation, le) (rate(inferadb_query_operation_duration_seconds_bucket[5m]))) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow query performance for {{ $labels.operation }}"
          description: "p99 latency is {{ $value }}s for operation {{ $labels.operation }}"

      # Condition evaluation failures
      - alert: HighConditionFailureRate
        expr: sum by (condition_type) (rate(inferadb_condition_evaluation_failure_total[5m])) / sum by (condition_type) (rate(inferadb_condition_evaluations_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High condition evaluation failure rate"
          description: "Condition type {{ $labels.condition_type }} has {{ $value | humanizePercentage }} failure rate"
```

---

## Metric Retention

Recommended retention periods:

- **Short-term (15 days)**: High-cardinality metrics like `inferadb_resource_checks_total`
- **Medium-term (60 days)**: Operation metrics, performance metrics
- **Long-term (1 year)**: Aggregated metrics, SLO tracking, build info

Configure retention in Prometheus:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

storage:
  tsdb:
    retention.time: 60d
    retention.size: 50GB
```

---

## Troubleshooting

### Metric Not Appearing

1. Check if InferaDB is exporting the metric:

   ```bash
   curl http://localhost:9090/metrics | grep inferadb_query_operations_total
   ```

2. Check Prometheus targets are up:

   ```text
   http://prometheus:9090/targets
   ```

3. Verify scrape configuration includes InferaDB

### High Cardinality Issues

If Prometheus is slow due to high cardinality:

1. Identify high-cardinality metrics:

   ```promql
   topk(10, count by (__name__) ({__name__=~"inferadb_.*"}))
   ```

2. Check label cardinality:

   ```promql
   count by (resource) (inferadb_resource_checks_total)
   ```

3. Consider using relabeling to drop or aggregate high-cardinality labels

---

## References

- [Prometheus Metric Types](https://prometheus.io/docs/concepts/metric_types/)
- [PromQL Queries](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/naming/)
- [InferaDB Grafana Dashboards](./README.md)
