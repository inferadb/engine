# Observability

InferaDB provides comprehensive observability through metrics, tracing, structured logging, and audit logging. This allows you to monitor performance, debug issues, ensure compliance, and understand system behavior in production.

## Overview

InferaDB's observability stack includes:

- **[Metrics](metrics.md)**: Prometheus-compatible metrics for monitoring performance
- **[Distributed Tracing](tracing.md)**: OpenTelemetry distributed tracing for request flow visualization
- **[Structured Logging](logging.md)**: Contextual logging with multiple output formats
- **[Audit Logging](auditing.md)**: Comprehensive audit trail for compliance and security

## Quick Start

### Metrics Endpoint

Access Prometheus-compatible metrics:

```bash
curl http://localhost:8080/metrics
```

### Enable Tracing

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_SERVICE_NAME=inferadb-engine
```

### Configure Logging

```bash
export INFERADB__ENGINE__LOGGING=info
export RUST_LOG=info,h2=warn,hyper=warn
```

### Enable Audit Logging

Audit logging is enabled by default. Configure log aggregation to capture audit events.

## Monitoring Stack

### Prometheus Setup

**prometheus.yml**:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "inferadb"
    static_configs:
      - targets: ["localhost:8080"]
    metrics_path: "/metrics"
```

**Start Prometheus**:

```bash
docker run -d --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

**Access**: <http://localhost:9090>

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
            "expr": "inferadb_engine_cache_hit_rate"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "sum(rate(inferadb_engine_api_errors_total[5m])) / sum(rate(inferadb_engine_api_requests_total[5m])) * 100"
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
        expr: sum(rate(inferadb_engine_api_errors_total[5m])) / sum(rate(inferadb_engine_api_requests_total[5m])) > 0.05
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
        expr: inferadb_engine_cache_hit_rate < 50
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

      # High replication lag
      - alert: HighReplicationLag
        expr: inferadb_engine_replication_lag_milliseconds > 100
        for: 5m
        annotations:
          summary: "High replication lag ({{ $value }}ms)"

      # Replication target unhealthy
      - alert: ReplicationTargetUnhealthy
        expr: (inferadb_engine_replication_targets_connected / inferadb_engine_replication_targets_total) < 1
        for: 2m
        annotations:
          summary: "Replication target unhealthy"
```

## Performance Monitoring

### Key Performance Indicators (KPIs)

1. **Request Rate**: `rate(inferadb_checks_total[5m])`
2. **p99 Latency**: `histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m]))`
3. **Error Rate**: `sum(rate(inferadb_engine_api_errors_total[5m])) / sum(rate(inferadb_engine_api_requests_total[5m]))`
4. **Cache Hit Rate**: `inferadb_engine_cache_hit_rate`
5. **Storage Throughput**: `rate(inferadb_storage_reads_total[5m]) + rate(inferadb_storage_writes_total[5m])`

### Performance Thresholds

**Latency**:

- p50 < 5ms (good)
- p90 < 10ms (acceptable)
- p99 < 50ms (threshold)
- p99 > 100ms (investigate)

**Cache Hit Rate**:

- > 90%: Excellent
- 70-90%: Good
- 50-70%: Acceptable
- < 50%: Poor (investigate)

**Error Rate**:

- < 0.1%: Excellent
- 0.1-1%: Acceptable
- 1-5%: Warning
- > 5%: Critical (alert)

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
- Replication lag (> 100ms)

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
- Splunk

### 6. Enable Audit Logging for Compliance

For production environments requiring compliance (SOC 2, GDPR, HIPAA, PCI DSS):

- Enable all audit event types
- Set sample rate to 100%
- Ship audit logs to SIEM
- Configure log retention per compliance requirements

## Observability Topics

### [Metrics](metrics.md)

Prometheus-compatible metrics covering:

- Authorization checks
- Cache performance
- Storage operations
- Authentication
- Replication
- WASM execution
- System metrics

### [Distributed Tracing](tracing.md)

OpenTelemetry tracing for:

- Request flow visualization
- Performance bottleneck identification
- Cross-service correlation
- Debugging complex authorization decisions

### [Structured Logging](logging.md)

Contextual logging with:

- Multiple output formats (JSON, compact)
- Log levels and filtering
- Span correlation
- Request context propagation

### [Audit Logging](auditing.md)

Comprehensive audit trail for:

- Authorization decisions
- Relationship mutations
- Resource/subject listings
- Compliance requirements
- Security monitoring
- SIEM integration

## Next Steps

- [Metrics Documentation](metrics.md) - Detailed metrics reference
- [Tracing Documentation](tracing.md) - Distributed tracing setup
- [Logging Documentation](logging.md) - Structured logging guide
- [Audit Logging Documentation](auditing.md) - Comprehensive audit guide
- [Performance Baselines](../performance.md) - Expected performance characteristics
- [Service Level Objectives](../slos.md) - SLO definitions and error budgets
