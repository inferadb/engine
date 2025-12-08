# InferaDB Alerting Best Practices

This guide provides best practices for setting up alerts and monitoring InferaDB authorization services in production.

## Table of Contents

- [Alert Philosophy](#alert-philosophy)
- [Alert Categories](#alert-categories)
- [Critical Alerts](#critical-alerts)
- [Warning Alerts](#warning-alerts)
- [Authorization-Specific Alerts](#authorization-specific-alerts)
- [Alert Configuration](#alert-configuration)
- [Notification Channels](#notification-channels)
- [Alert Runbooks](#alert-runbooks)
- [Testing Alerts](#testing-alerts)

---

## Alert Philosophy

### What to Alert On

**DO alert on**:

- **Symptoms**: User-visible problems (high latency, errors, unavailability)
- **Impact**: Events that affect SLOs or SLAs
- **Urgent issues**: Problems requiring immediate human intervention

**DON'T alert on**:

- **Metrics for information only**: High CPU is fine if latency is good
- **Self-healing issues**: Automatic retries, temporary spikes
- **Non-urgent issues**: Things that can wait for business hours

### Alert Severity Levels

- **Critical (Page)**: Immediate action required, affects users now
- **Warning (Ticket)**: Requires attention soon, may affect users if not addressed
- **Info (Log)**: For informational purposes, investigate when convenient

---

## Alert Categories

### 1. Availability Alerts

Monitor service uptime and health

### 2. Latency Alerts

Monitor response times and SLO compliance

### 3. Error Rate Alerts

Monitor authorization decision errors and API errors

### 4. Saturation Alerts

Monitor resource utilization approaching limits

### 5. Authorization-Specific Alerts

Monitor authorization patterns and anomalies

---

## Critical Alerts

### 1. Service Down

**Severity**: Critical (Page immediately)

**Alert Rule**:

```yaml
- alert: InferaDBServiceDown
  expr: up{job="inferadb"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "InferaDB service is down"
    description: "InferaDB instance {{ $labels.instance }} has been down for more than 1 minute"
    runbook_url: "https://runbooks.inferadb.com/service-down"
```

**What it means**: The InferaDB service is not responding to health checks

**Actions**:

1. Check service logs for crash/panic
2. Verify infrastructure (networking, DNS, load balancer)
3. Check resource availability (memory, disk, CPU)
4. Restart service if necessary
5. Investigate root cause after recovery

---

### 2. High Error Rate

**Severity**: Critical (Page immediately)

**Alert Rule**:

```yaml
- alert: InferaDBHighErrorRate
  expr: |
    sum(rate(inferadb_engine_api_errors_total{status=~"5.."}[5m])) /
    sum(rate(inferadb_engine_api_requests_total[5m])) > 0.05
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "InferaDB has high error rate"
    description: "Error rate is {{ $value | humanizePercentage }} (threshold: 5%)"
    runbook_url: "https://runbooks.inferadb.com/high-error-rate"
```

**What it means**: More than 5% of requests are failing with 5xx errors

**Actions**:

1. Check error logs for specific error types
2. Verify database connectivity (FoundationDB)
3. Check for OOM or resource exhaustion
4. Review recent deployments or configuration changes
5. Consider rolling back if caused by recent change

---

### 3. SLO Breach - p99 Latency

**Severity**: Critical (Page immediately)

**Alert Rule**:

```yaml
- alert: InferaDBLatencySLOBreach
  expr: |
    histogram_quantile(0.99,
      rate(inferadb_check_duration_seconds_bucket[5m])
    ) > 0.010
  for: 10m
  labels:
    severity: critical
  annotations:
    summary: "InferaDB p99 latency exceeds SLO"
    description: "p99 latency is {{ $value }}s (SLO: 10ms)"
    runbook_url: "https://runbooks.inferadb.com/latency-slo-breach"
```

**What it means**: 99th percentile latency exceeds 10ms target

**Actions**:

1. Check database latency (FoundationDB performance)
2. Review evaluation complexity (depth, branches)
3. Check cache hit rate
4. Look for expensive WASM modules
5. Review recent schema or policy changes

---

### 4. Error Budget Exhausted

**Severity**: Critical (Page during business hours)

**Alert Rule**:

```yaml
- alert: InferaDBErrorBudgetExhausted
  expr: |
    (0.001 - (
      sum(rate(inferadb_engine_api_errors_total{status=~"5.."}[30d])) /
      sum(rate(inferadb_checks_total[30d]))
    )) / 0.001 < 0.1
  for: 1h
  labels:
    severity: critical
  annotations:
    summary: "InferaDB error budget nearly exhausted"
    description: "Error budget remaining: {{ $value | humanizePercentage }}"
    runbook_url: "https://runbooks.inferadb.com/error-budget"
```

**What it means**: Less than 10% of monthly error budget remains

**Actions**:

1. Freeze non-essential deployments
2. Focus on reliability improvements
3. Investigate primary error sources
4. Consider feature freeze until budget recovers

---

## Warning Alerts

### 1. Elevated Error Rate

**Severity**: Warning (Create ticket)

**Alert Rule**:

```yaml
- alert: InferaDBElevatedErrorRate
  expr: |
    sum(rate(inferadb_engine_api_errors_total{status=~"5.."}[5m])) /
    sum(rate(inferadb_engine_api_requests_total[5m])) > 0.01
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "InferaDB has elevated error rate"
    description: "Error rate is {{ $value | humanizePercentage }} (threshold: 1%)"
    runbook_url: "https://runbooks.inferadb.com/elevated-errors"
```

**What it means**: Error rate is elevated but not critical

**Actions**:

1. Monitor for escalation to critical threshold
2. Review error logs for patterns
3. Check for specific endpoints with high errors
4. Schedule investigation if trend continues

---

### 2. Low Cache Hit Rate

**Severity**: Warning (Create ticket)

**Alert Rule**:

```yaml
- alert: InferaDBLowCacheHitRate
  expr: |
    sum(rate(inferadb_engine_cache_hits_total[5m])) /
    (sum(rate(inferadb_engine_cache_hits_total[5m])) +
     sum(rate(inferadb_engine_cache_misses_total[5m]))) < 0.80
  for: 30m
  labels:
    severity: warning
  annotations:
    summary: "InferaDB cache hit rate is low"
    description: "Cache hit rate is {{ $value | humanizePercentage }} (target: >80%)"
    runbook_url: "https://runbooks.inferadb.com/low-cache-hit-rate"
```

**What it means**: Cache is not effectively reducing database load

**Actions**:

1. Check cache size configuration
2. Review TTL settings
3. Analyze access patterns for optimization
4. Consider increasing cache size if memory available

---

### 3. Slow Query Performance

**Severity**: Warning (Create ticket)

**Alert Rule**:

```yaml
- alert: InferaDBSlowQueryPerformance
  expr: |
    histogram_quantile(0.99,
      sum by (operation, le) (
        rate(inferadb_query_operation_duration_seconds_bucket[5m])
      )
    ) > 0.050
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "Slow query performance for {{ $labels.operation }}"
    description: "p99 latency is {{ $value }}s for operation {{ $labels.operation }}"
    runbook_url: "https://runbooks.inferadb.com/slow-queries"
```

**What it means**: Specific operation types are slower than expected

**Actions**:

1. Identify which operations are slow
2. Review evaluation complexity for those operations
3. Check for expensive conditions or WASM modules
4. Consider optimization or caching improvements

---

### 4. High Condition Evaluation Failure Rate

**Severity**: Warning (Create ticket)

**Alert Rule**:

```yaml
- alert: InferaDBHighConditionFailureRate
  expr: |
    sum by (condition_type) (
      rate(inferadb_condition_evaluation_failure_total[5m])
    ) /
    sum by (condition_type) (
      rate(inferadb_condition_evaluations_total[5m])
    ) > 0.05
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "High condition evaluation failure rate"
    description: "Condition type {{ $labels.condition_type }} has {{ $value | humanizePercentage }} failure rate"
    runbook_url: "https://runbooks.inferadb.com/condition-failures"
```

**What it means**: WASM modules or conditions are failing frequently

**Actions**:

1. Review WASM module logs for errors
2. Check fuel limits
3. Verify condition logic and inputs
4. Consider disabling problematic conditions temporarily

---

## Authorization-Specific Alerts

### 1. Unusual Access Pattern

**Severity**: Warning (Investigate)

**Alert Rule**:

```yaml
- alert: InferaDBUnusualAccessPattern
  expr: |
    topk(1,
      sum by (subject) (
        rate(inferadb_subject_checks_total[5m])
      )
    ) > 100
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "Unusual access pattern detected"
    description: "Subject {{ $labels.subject }} has {{ $value }} checks/sec"
    runbook_url: "https://runbooks.inferadb.com/unusual-access"
```

**What it means**: A subject is making an unusually high number of authorization checks

**Actions**:

1. Verify if this is expected behavior (batch job, etc.)
2. Check for potential abuse or misconfiguration
3. Review logs for the specific subject
4. Consider rate limiting if abusive

---

### 2. High Deny Rate for Specific Subject

**Severity**: Info (Monitor)

**Alert Rule**:

```yaml
- alert: InferaDBHighDenyRateForSubject
  expr: |
    sum by (subject) (
      rate(inferadb_checks_denied_total[5m])
    ) > 10
  for: 30m
  labels:
    severity: info
  annotations:
    summary: "High deny rate for subject {{ $labels.subject }}"
    description: "Subject has {{ $value }} denials/sec for 30+ minutes"
    runbook_url: "https://runbooks.inferadb.com/high-deny-rate"
```

**What it means**: A specific subject is being denied access frequently

**Actions**:

1. Check if subject has correct permissions
2. Review for potential security issues
3. Verify application logic is correct
4. Consider user education or UX improvements

---

### 3. Spike in Permission Checks

**Severity**: Info (Monitor)

**Alert Rule**:

```yaml
- alert: InferaDBPermissionCheckSpike
  expr: |
    sum by (permission) (
      rate(inferadb_permission_checks_total[5m])
    ) /
    sum by (permission) (
      rate(inferadb_permission_checks_total[5m] offset 1h)
    ) > 5
  for: 10m
  labels:
    severity: info
  annotations:
    summary: "Spike in {{ $labels.permission }} permission checks"
    description: "Check rate increased by {{ $value }}x compared to 1h ago"
    runbook_url: "https://runbooks.inferadb.com/permission-spike"
```

**What it means**: Specific permission is being checked much more than usual

**Actions**:

1. Verify if this is expected (new feature, marketing campaign, etc.)
2. Check for application bugs causing excessive checks
3. Ensure infrastructure can handle the load
4. Consider implementing request deduplication

---

## Alert Configuration

### Prometheus AlertManager Configuration

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ["alertname", "cluster", "service"]
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: "default"
  routes:
    - match:
        severity: critical
      receiver: "pagerduty-critical"
      group_wait: 0s
      continue: true
    - match:
        severity: warning
      receiver: "slack-warnings"
    - match:
        severity: info
      receiver: "slack-info"

receivers:
  - name: "default"
    slack_configs:
      - api_url: "https://hooks.slack.com/services/xxx"
        channel: "#inferadb-alerts"
        title: "{{ .GroupLabels.alertname }}"
        text: "{{ range .Alerts }}{{ .Annotations.description }}{{ end }}"

  - name: "pagerduty-critical"
    pagerduty_configs:
      - service_key: "YOUR_PAGERDUTY_KEY"
        description: "{{ .GroupLabels.alertname }}"

  - name: "slack-warnings"
    slack_configs:
      - api_url: "https://hooks.slack.com/services/xxx"
        channel: "#inferadb-warnings"
        color: "warning"

  - name: "slack-info"
    slack_configs:
      - api_url: "https://hooks.slack.com/services/xxx"
        channel: "#inferadb-info"
        color: "good"
```

---

## Notification Channels

### Recommended Setup

1. **Critical Alerts → PagerDuty**
   - Immediate escalation
   - On-call rotation
   - SMS/Phone notifications

2. **Warning Alerts → Slack #inferadb-warnings**
   - Creates Jira ticket automatically
   - Reviews during business hours
   - Weekly triage meeting

3. **Info Alerts → Slack #inferadb-info**
   - Optional monitoring
   - Good for trends and analytics
   - No immediate action required

---

## Alert Runbooks

Each alert should have a runbook URL in annotations. Runbook format:

````markdown
# Alert: InferaDBHighErrorRate

## Severity

Critical - Page immediately

## Symptoms

- Error rate exceeds 5%
- Users seeing 5xx errors
- Authorization checks failing

## Impact

- Users cannot access resources
- Applications may fail
- SLO breach imminent

## Diagnosis

1. Check error logs:
   ```bash
   kubectl logs -l app=inferadb --tail=100 | grep ERROR
   ```
````

1. Check specific error types:

   ```promql
   topk(10, sum by (error_type) (rate(inferadb_engine_api_errors_total[5m])))
   ```

2. Verify database connectivity:

   ```bash
   fdbcli --exec "status"
   ```

## Resolution

1. If database issue: Contact DBA, check FoundationDB cluster
2. If resource exhaustion: Scale up InferaDB pods
3. If bad deployment: Rollback to previous version
4. If WASM errors: Disable problematic WASM modules

## Escalation

- On-call SRE → InferaDB team lead → Director of Engineering

---

## Testing Alerts

### Alert Testing Checklist

1. **Verify Alert Fires**:

   ```bash
   # Manually trigger condition
   curl -X POST http://inferadb/test/trigger-errors

   # Verify alert fires in Prometheus
   # http://prometheus:9090/alerts
   ```

2. **Verify Notification Delivery**:
   - Check Slack channel receives message
   - Verify PagerDuty incident created
   - Confirm ticket created in Jira

3. **Verify Alert Resolves**:
   - Wait for condition to clear
   - Verify alert auto-resolves
   - Check resolution notification sent

4. **Test Runbook**:
   - Follow runbook steps exactly as written
   - Verify all commands work
   - Update runbook with learnings

### Monthly Alert Review

Schedule monthly review to:

1. **Review alert frequency**:

   ```promql
   count by (alertname) (ALERTS{alertstate="firing"} offset 30d)
   ```

2. **Identify noisy alerts** (too many false positives)
3. **Adjust thresholds** based on actual behavior
4. **Archive unused alerts**
5. **Add new alerts** for newly discovered issues

---

## Alert Threshold Tuning

### Methodology

1. **Baseline Collection** (2-4 weeks):
   - Collect metrics without alerts
   - Analyze normal behavior patterns
   - Identify outliers and anomalies

2. **Initial Thresholds**:
   - Set conservative (loose) thresholds
   - Expect some false positives
   - Better to alert than miss issue

3. **Tuning Period** (4-8 weeks):
   - Track false positive rate
   - Adjust thresholds based on feedback
   - Document why changes were made

4. **Steady State**:
   - Review quarterly
   - Adjust for seasonal patterns
   - Update for new features

### Example Tuning Log

```yaml
alert: InferaDBHighErrorRate
history:
  - date: 2024-01-15
    threshold: 0.01 (1%)
    reason: "Initial conservative threshold"

  - date: 2024-02-03
    threshold: 0.02 (2%)
    reason: "Too many false positives during deploy windows"

  - date: 2024-03-10
    threshold: 0.015 (1.5%)
    reason: "Missed real incident at 2%, adjusting down"

  - date: 2024-04-22
    threshold: 0.05 (5%)
    reason: "Database maintenance causes temporary spikes to 3%, increasing threshold"
```

---

## Best Practices Summary

1. **Alert on symptoms, not causes**
   - Alert on user impact (latency, errors)
   - Not on resource metrics (CPU, memory) unless causing impact

2. **Make alerts actionable**
   - Every alert should have a runbook
   - Clear steps for resolution
   - Escalation path defined

3. **Reduce alert fatigue**
   - Tune thresholds to minimize false positives
   - Group related alerts
   - Use appropriate severity levels

4. **Test your alerts**
   - Regularly trigger alerts in staging
   - Verify notifications work
   - Practice runbooks

5. **Review and improve**
   - Monthly alert review
   - Update runbooks based on incidents
   - Remove alerts that don't provide value

6. **Use SLO-based alerting**
   - Alert on error budget burn rate
   - Multi-window multi-burn-rate alerts
   - Balance fast detection with low false positives

---

## References

- [Google SRE Book - Monitoring Distributed Systems](https://sre.google/sre-book/monitoring-distributed-systems/)
- [Prometheus Alerting Best Practices](https://prometheus.io/docs/practices/alerting/)
- [The Four Golden Signals](https://sre.google/sre-book/monitoring-distributed-systems/#xref_monitoring_golden-signals)
- [InferaDB Metrics Reference](./METRICS_REFERENCE.md)
- [InferaDB Dashboard Documentation](./README.md)
