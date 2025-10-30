# InferaDB Alerting Guide

This document explains how to deploy and manage InferaDB's Prometheus alerting rules.

## Overview

InferaDB uses **multi-window, multi-burn-rate alerts** to catch SLO violations early while minimizing false positives. All alerts are based on the Service Level Objectives (SLOs) defined in [../docs/slos.md](../docs/slos.md).

## Alert Severity Levels

| Severity          | Description                                | Response Time | Action Required                     |
| ----------------- | ------------------------------------------ | ------------- | ----------------------------------- |
| **P0 (Critical)** | SLO violation in progress, customer impact | Immediate     | Page on-call engineer               |
| **P1 (High)**     | SLO at risk, trending toward violation     | 15 minutes    | Notify on-call engineer             |
| **P2 (Medium)**   | SLO warning, early indicator               | 1 hour        | Create ticket for next business day |
| **P3 (Low)**      | Informational, no immediate action needed  | None          | Log and review in weekly meeting    |

## Alert Categories

### SLO-Based Alerts

Alerts that directly track SLO compliance:

- **Availability SLO** (`slo: availability`)

  - Fast burn: 14.4x burn rate over 1 hour
  - Slow burn: 3x burn rate over 24 hours
  - Violation: 30-day error rate exceeds 0.1%
  - Budget warning: Error budget 50% consumed

- **Latency SLO** (`slo: latency`)

  - p99 > 10ms (critical)
  - p99 > 8ms (warning)
  - p50 > 2ms, p90 > 5ms (degradation)
  - WASM p99 > 50ms

- **Error Rate SLO** (`slo: error_rate`)

  - Error rate > 0.1%
  - Error rate > 0.05% (warning)

- **Cache Hit Rate SLO** (`slo: cache`)

  - Hit rate < 80% (target)
  - Hit rate < 60% (critical)

- **Storage Latency SLO** (`slo: storage_latency`)

  - Read/write p99 > 5ms
  - Read/write p99 > 4ms (warning)

- **Replication Lag SLO** (`slo: replication`)

  - Lag > 100ms (target)
  - Lag > 500ms (critical)

- **JWKS Freshness SLO** (`slo: jwks`)

  - Stale serving > 1/sec

- **Evaluation Depth SLO** (`slo: evaluation`)
  - p99 > 10 levels
  - p99 > 20 levels (critical)

### Component-Specific Alerts

Alerts for specific system components:

- **Errors** (`category: errors`)

  - Storage errors
  - Evaluation errors

- **Cache** (`category: cache`)

  - High eviction rate

- **Replication** (`category: replication`)

  - Target unhealthy
  - High error rate
  - High conflict rate

- **Auth** (`category: auth`)

  - JWKS refresh failures

- **Capacity** (`category: capacity`)

  - CPU utilization > 70%
  - Memory utilization > 80%
  - Rapidly increasing request rate

- **Health** (`category: health`)
  - Service down
  - Goroutine leak suspected
  - File descriptor usage high

## Deployment

### Prerequisites

- Prometheus 2.x or later
- AlertManager configured and running
- InferaDB exporting metrics to Prometheus

### Step 1: Configure Prometheus

Add InferaDB as a scrape target in `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "inferadb"
    scrape_interval: 15s
    static_configs:
      - targets: ["localhost:9090"] # Adjust to your InferaDB metrics endpoint
        labels:
          environment: "production"
          region: "us-west-1"
```

### Step 2: Load Alerting Rules

Add the alerting rules to your Prometheus configuration:

```yaml
# prometheus.yml
rule_files:
  - "alerting-rules.yml"
```

Or if using Prometheus Operator (Kubernetes):

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: inferadb-alerts
  namespace: monitoring
spec:
  groups:
    # Copy groups from alerting-rules.yml here
```

### Step 3: Configure AlertManager

Configure AlertManager to route InferaDB alerts appropriately:

```yaml
# alertmanager.yml
route:
  receiver: "default"
  group_by: ["alertname", "category", "severity"]
  group_wait: 10s
  group_interval: 5m
  repeat_interval: 4h

  routes:
    # P0 alerts - page immediately
    - match:
        severity: P0
      receiver: "pagerduty-critical"
      continue: true

    # P1 alerts - notify on-call
    - match:
        severity: P1
      receiver: "slack-oncall"
      continue: true

    # P2 alerts - create ticket
    - match:
        severity: P2
      receiver: "jira-tickets"

    # P3 alerts - log only
    - match:
        severity: P3
      receiver: "null"

receivers:
  - name: "default"
    # Default catch-all

  - name: "pagerduty-critical"
    pagerduty_configs:
      - service_key: "<your-pagerduty-key>"
        severity: "critical"

  - name: "slack-oncall"
    slack_configs:
      - api_url: "<your-slack-webhook>"
        channel: "#inferadb-alerts"
        title: "{{ .GroupLabels.alertname }}"
        text: "{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}"

  - name: "jira-tickets"
    webhook_configs:
      - url: "<your-jira-webhook>"

  - name: "null"
    # Discard P3 alerts
```

### Step 4: Verify Alerts

Check that Prometheus has loaded the rules:

```bash
# Check rules are loaded
curl http://localhost:9090/api/v1/rules | jq '.data.groups[].name'

# Check for firing alerts
curl http://localhost:9090/api/v1/alerts | jq '.data.alerts[] | select(.state=="firing")'
```

### Step 5: Test Alerts

Trigger a test alert to verify the pipeline:

```bash
# In AlertManager, you can create a test alert:
curl -X POST http://localhost:9093/api/v1/alerts -d '[
  {
    "labels": {
      "alertname": "TestAlert",
      "severity": "P3"
    },
    "annotations": {
      "summary": "This is a test alert"
    }
  }
]'
```

## Alert Runbooks

Each alert includes a `runbook_url` annotation pointing to troubleshooting steps. Create runbooks for:

### Availability SLO Runbook

**URL**: `https://docs.inferadb.dev/runbooks/availability-slo`

**Steps**:

1. Check dashboard for error spike
2. Identify affected endpoints/regions
3. Check recent deployments (rollback if needed)
4. Review error logs for root cause
5. Scale infrastructure if capacity issue
6. Update incident timeline
7. Create postmortem when resolved

### Latency SLO Runbook

**URL**: `https://docs.inferadb.dev/runbooks/latency-slo`

**Steps**:

1. Check which percentile is affected (p50/p90/p99)
2. Review cache hit rate - low cache hits cause latency
3. Check storage latency metrics
4. Examine evaluation depth - deep trees slow checks
5. Look for WASM policy complexity
6. Check for network issues to storage backend
7. Scale if CPU/memory constrained

### Error Rate SLO Runbook

**URL**: `https://docs.inferadb.dev/runbooks/error-rate-slo`

**Steps**:

1. Identify error types (storage, evaluation, auth)
2. Check storage backend health
3. Review evaluation errors for policy issues
4. Check auth configuration (JWKS, OAuth)
5. Review logs for stack traces
6. Rollback recent changes if applicable

### Cache SLO Runbook

**URL**: `https://docs.inferadb.dev/runbooks/cache-slo`

**Steps**:

1. Check current cache size and memory usage
2. Review eviction rate - high evictions indicate undersizing
3. Analyze workload - write-heavy workloads have lower hit rates
4. Consider increasing cache size or TTL
5. Check for cache poisoning (invalid entries)

### Storage Latency SLO Runbook

**URL**: `https://docs.inferadb.dev/runbooks/storage-latency-slo`

**Steps**:

1. Check storage backend metrics (FoundationDB, etc.)
2. Review slow query logs
3. Check for storage capacity issues
4. Look for network latency to storage
5. Consider scaling storage tier
6. Optimize queries if possible

### Replication Lag SLO Runbook

**URL**: `https://docs.inferadb.dev/runbooks/replication-lag-slo`

**Steps**:

1. Identify which region has high lag
2. Check network latency between regions
3. Review replication target health
4. Check for backpressure (slow consumer)
5. Examine conflict rate - high conflicts slow replication
6. Increase replication batch size if network-bound
7. Add bandwidth if network-constrained

### JWKS SLO Runbook

**URL**: `https://docs.inferadb.dev/runbooks/jwks-slo`

**Steps**:

1. Check JWKS refresh errors
2. Verify OAuth provider is reachable
3. Review network connectivity to JWKS endpoint
4. Check for cert/TLS issues
5. Increase JWKS cache TTL if provider is slow
6. Fall back to cached keys if provider down

### Evaluation Depth SLO Runbook

**URL**: `https://docs.inferadb.dev/runbooks/evaluation-depth-slo`

**Steps**:

1. Identify which policies have deep trees
2. Check for circular references in policies
3. Review hierarchical org structures
4. Consider policy optimization (flatten hierarchy)
5. Add caching for intermediate results
6. Set evaluation depth limits

### Service Down Runbook

**URL**: `https://docs.inferadb.dev/runbooks/service-down`

**Steps**:

1. Check process is running
2. Review service logs for crash/panic
3. Check infrastructure (VM, container)
4. Verify network connectivity
5. Check resource constraints (OOM, disk full)
6. Restart service if needed
7. Investigate crash dump if available

## Alert Fatigue Prevention

### Silencing Alerts

Silence alerts during maintenance windows:

```bash
# Silence all alerts for 2 hours
curl -X POST http://localhost:9093/api/v1/silences -d '{
  "matchers": [{"name": "job", "value": "inferadb", "isRegex": false}],
  "startsAt": "2025-01-15T10:00:00Z",
  "endsAt": "2025-01-15T12:00:00Z",
  "createdBy": "ops-team",
  "comment": "Scheduled maintenance"
}'
```

### Adjusting Thresholds

If alerts are too noisy:

1. Review alert history to identify false positives
2. Adjust `for` duration to require sustained violations
3. Adjust thresholds based on actual baseline performance
4. Consider time-of-day adjustments for known traffic patterns

### Alert Tuning Process

1. **Week 1**: Deploy with conservative thresholds
2. **Week 2-4**: Collect data on alert frequency and accuracy
3. **Month 2**: Adjust thresholds based on actual SLO performance
4. **Quarterly**: Review and refine alerts based on incidents

## Monitoring Alert Health

Track alerting system health:

```promql
# Alerts firing
ALERTS{alertstate="firing"}

# Alert firing rate
rate(ALERTS[5m])

# Top firing alerts
topk(10, count by (alertname) (ALERTS{alertstate="firing"}))

# Alert resolution time
histogram_quantile(0.99, rate(alertmanager_notification_latency_seconds_bucket[5m]))
```

## Integration Examples

### Slack Integration

```yaml
receivers:
  - name: "slack-alerts"
    slack_configs:
      - api_url: "<webhook-url>"
        channel: "#inferadb-alerts"
        title: ":fire: {{ .GroupLabels.alertname }}"
        text: |
          {{ range .Alerts }}
          *Severity*: {{ .Labels.severity }}
          *Summary*: {{ .Annotations.summary }}
          *Description*: {{ .Annotations.description }}
          {{ if .Annotations.runbook_url }}*Runbook*: {{ .Annotations.runbook_url }}{{ end }}
          {{ if .Annotations.dashboard_url }}*Dashboard*: {{ .Annotations.dashboard_url }}{{ end }}
          {{ end }}
        send_resolved: true
```

### PagerDuty Integration

```yaml
receivers:
  - name: "pagerduty-critical"
    pagerduty_configs:
      - service_key: "<integration-key>"
        severity: "{{ .Labels.severity }}"
        description: "{{ .Annotations.summary }}"
        details:
          firing: "{{ range .Alerts }}{{ .Annotations.description }}{{ end }}"
          dashboard: "{{ .Annotations.dashboard_url }}"
          runbook: "{{ .Annotations.runbook_url }}"
```

### Jira Integration

```yaml
receivers:
  - name: "jira-tickets"
    webhook_configs:
      - url: "https://your-jira-instance/rest/api/2/issue"
        http_config:
          basic_auth:
            username: "<jira-user>"
            password: "<jira-token>"
        send_resolved: false
```

## References

- [Prometheus Alerting Documentation](https://prometheus.io/docs/alerting/latest/overview/)
- [AlertManager Configuration](https://prometheus.io/docs/alerting/latest/configuration/)
- [Google SRE Book - Alerting on SLOs](https://sre.google/workbook/alerting-on-slos/)
- [InferaDB SLO Documentation](../docs/slos.md)
- [InferaDB Observability Guide](../docs/observability.md)

## Support

For questions or issues with alerting:

1. Review runbooks linked in alert annotations
2. Check [../docs/observability.md](../docs/observability.md) for metric definitions
3. Consult [../docs/slos.md](../docs/slos.md) for SLO rationale
4. Open an issue in the InferaDB repository
