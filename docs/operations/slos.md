# Service Level Objectives (SLOs)

This document defines InferaDB's Service Level Indicators (SLIs) and Service Level Objectives (SLOs) for production deployments.

## Overview

SLOs define the target reliability and performance characteristics for InferaDB. These objectives guide operational decisions, capacity planning, and incident response priorities.

## Core SLOs

### 1. Availability SLO

**Target: 99.9% (three nines)**

**Definition**: Percentage of time the service successfully responds to requests.

**SLI Calculation**:

```promql
# Availability over 30 days
sum(rate(inferadb_checks_total[30d])) - sum(rate(inferadb_engine_api_errors_total{code=~"5.."}[30d]))
/ sum(rate(inferadb_checks_total[30d])) * 100
```

**Error Budget**: 0.1% = 43.8 minutes downtime per month

**Measurement Window**: 30-day rolling window

**Exclusions**:

- Scheduled maintenance (with 48h notice)
- Client errors (4xx status codes)
- DDoS attacks
- Third-party service failures (OAuth provider, JWKS endpoint)

**Rationale**: 99.9% provides a balance between reliability and operational flexibility for an authorization service. Higher availability (99.99%) requires significantly more infrastructure investment.

---

### 2. Request Latency SLO

**Target: p99 < 10ms for authorization checks**

**Definition**: 99th percentile of authorization check latency must be below 10 milliseconds.

**SLI Calculation**:

```promql
# p99 latency for checks
histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m])) * 1000
```

**Additional Targets**:

- **p50 < 2ms**: Median latency for typical requests
- **p90 < 5ms**: 90th percentile latency
- **p99.9 < 50ms**: Tail latency for complex evaluations

**Measurement Window**: 5-minute rolling window

**Exclusions**:

- Requests with WASM policy execution (tracked separately)
- First request after cold start
- Requests during cache warming

**Rationale**: Authorization is on the critical path for user requests. 10ms p99 allows for authorization checks without significantly impacting user-perceived latency (typical web requests: 100-200ms).

**WASM Latency SLO**:

- **Target**: p99 < 50ms for WASM-enhanced checks
- WASM execution adds overhead but enables custom policies

---

### 3. Error Rate SLO

**Target: < 0.1% error rate**

**Definition**: Less than 0.1% of requests result in 5xx server errors.

**SLI Calculation**:

```promql
# Error rate over 5 minutes
sum(rate(inferadb_engine_api_errors_total{code=~"5.."}[5m]))
/ sum(rate(inferadb_checks_total[5m])) * 100
```

**Measurement Window**: 5-minute rolling window

**Error Budget**: 1 error per 1,000 requests

**Exclusions**:

- Client errors (4xx): validation errors, auth failures, not found
- Rate limit errors (429)
- Upstream service failures (if properly handled)

**Rationale**: Authorization services must be highly reliable. 0.1% error rate ensures that authorization doesn't become a common source of application failures.

---

### 4. Cache Hit Rate SLO

**Target: > 80% cache hit rate**

**Definition**: At least 80% of authorization checks should be served from cache.

**SLI Calculation**:

```promql
# Cache hit rate
sum(rate(inferadb_engine_cache_hits_total[5m]))
/ (sum(rate(inferadb_engine_cache_hits_total[5m])) + sum(rate(inferadb_engine_cache_misses_total[5m]))) * 100
```

**Measurement Window**: 5-minute rolling window

**Rationale**: Caching is critical for performance. 80% hit rate significantly reduces storage load and improves latency. Lower hit rates may indicate cache sizing issues or workload characteristics.

**Note**: Hit rate varies by workload. Read-heavy workloads may achieve >95%, while write-heavy workloads may see <70%.

---

### 5. Storage Operation Latency SLO

**Target: p99 < 5ms for storage operations**

**Definition**: 99th percentile of storage read/write operations must complete within 5 milliseconds.

**SLI Calculation**:

```promql
# p99 storage read latency
histogram_quantile(0.99, rate(inferadb_storage_read_duration_seconds_bucket[5m])) * 1000

# p99 storage write latency
histogram_quantile(0.99, rate(inferadb_storage_write_duration_seconds_bucket[5m])) * 1000
```

**Measurement Window**: 5-minute rolling window

**Rationale**: Fast storage operations are essential for low authorization latency. 5ms target accounts for disk I/O (memory backend: <1ms, FoundationDB: 2-5ms).

---

### 6. Replication Lag SLO

**Target: < 100ms replication lag**

**Definition**: Changes should replicate to remote regions within 100 milliseconds.

**SLI Calculation**:

```promql
# Current replication lag
inferadb_engine_replication_lag_milliseconds
```

**Measurement Window**: Real-time gauge

**Rationale**: Low replication lag ensures data consistency across regions. 100ms provides near-real-time replication while accounting for network latency and batching.

---

## Secondary SLOs

### 7. JWKS Cache Freshness

**Target: < 1 second stale JWKS serving**

**Definition**: Stale JWKS keys should be served for less than 1 second during refresh.

**SLI Calculation**:

```promql
# Stale serves per minute
rate(inferadb_jwks_stale_served_total[1m])
```

**Rationale**: Stale JWKS can cause valid tokens to be rejected. 1 second allows for background refresh while minimizing impact.

### 8. Evaluation Depth

**Target: p99 < 10 levels**

**Definition**: 99% of authorization checks should resolve within 10 levels of graph traversal.

**SLI Calculation**:

```promql
# p99 evaluation depth
histogram_quantile(0.99, rate(inferadb_evaluation_depth_bucket[5m]))
```

**Rationale**: Deep evaluation trees indicate complex policies or potential circular references. 10 levels accommodates hierarchical organizations without excessive overhead.

---

## SLO Measurement and Reporting

### Monitoring Frequency

- **Real-time**: Dashboard updates every 30 seconds
- **Alerting**: 1-minute evaluation windows for fast response
- **Reporting**: Daily SLO reports, weekly trends, monthly compliance

### SLO Compliance Dashboard

Key metrics to display:

```promql
# Availability (30-day)
1 - (sum(rate(inferadb_engine_api_errors_total{code=~"5.."}[30d]))
/ sum(rate(inferadb_checks_total[30d])))

# Latency (5-minute)
histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m]))

# Error Rate (5-minute)
sum(rate(inferadb_engine_api_errors_total{code=~"5.."}[5m]))
/ sum(rate(inferadb_checks_total[5m]))

# Cache Hit Rate (5-minute)
sum(rate(inferadb_engine_cache_hits_total[5m]))
/ (sum(rate(inferadb_engine_cache_hits_total[5m])) + sum(rate(inferadb_engine_cache_misses_total[5m])))

# Error Budget Remaining (30-day)
(0.001 - (sum(rate(inferadb_engine_api_errors_total{code=~"5.."}[30d]))
/ sum(rate(inferadb_checks_total[30d])))) * 100
```

### Error Budget Policy

**When error budget is exhausted (SLO missed)**:

1. **Freeze non-critical changes**: No new features, only reliability improvements
2. **Root cause analysis**: Investigate and document the incident
3. **Implement fixes**: Address underlying causes before resuming feature work
4. **Postmortem**: Share learnings with team

**When error budget is healthy (>50% remaining)**:

- Normal feature development continues
- May take calculated risks on performance optimizations
- Can deploy more frequently

---

## SLO Alerting Strategy

### Alert Severity Levels

| Severity          | Description                                | Response Time | Escalation                   |
| ----------------- | ------------------------------------------ | ------------- | ---------------------------- |
| **P0 (Critical)** | SLO violation in progress, customer impact | Immediate     | Page on-call                 |
| **P1 (High)**     | SLO at risk, trending toward violation     | 15 minutes    | Notify on-call               |
| **P2 (Medium)**   | SLO warning, early indicator               | 1 hour        | Ticket for next business day |
| **P3 (Low)**      | SLO healthy, informational                 | None          | Log only                     |

### Alert Burn Rate

Use **multi-window, multi-burn-rate alerts** to catch SLO violations early while reducing false positives.

**Example: Availability SLO (99.9% target)**

```yaml
# Fast burn (1h window): 14.4x burn rate = 0.1% error budget in 1h
- alert: AvailabilitySLOFastBurn
  expr: |
    sum(rate(inferadb_engine_api_errors_total{code=~"5.."}[1h]))
    / sum(rate(inferadb_checks_total[1h])) > 0.0144
  for: 5m
  labels:
    severity: P0
  annotations:
    summary: "Fast availability SLO burn"
    description: "Error rate {{ $value }} exceeds 1.44% (14.4x burn rate)"

# Slow burn (24h window): 3x burn rate = 0.1% error budget in 24h
- alert: AvailabilitySLOSlowBurn
  expr: |
    sum(rate(inferadb_engine_api_errors_total{code=~"5.."}[24h]))
    / sum(rate(inferadb_checks_total[24h])) > 0.003
  for: 1h
  labels:
    severity: P1
  annotations:
    summary: "Slow availability SLO burn"
    description: "Error rate {{ $value }} exceeds 0.3% (3x burn rate)"
```

---

## SLO Targets by Environment

### Production

- Availability: 99.9%
- Latency p99: <10ms
- Error rate: <0.1%
- Cache hit rate: >80%

### Staging

- Availability: 99.5%
- Latency p99: <20ms
- Error rate: <0.5%
- Cache hit rate: >70%

### Development

- No strict SLOs (best effort)
- Used for testing and experimentation

---

## SLO Review Process

### Monthly SLO Review

**Agenda**:

1. Review SLO compliance for past 30 days
2. Analyze error budget spend
3. Review incidents and root causes
4. Identify trends and patterns
5. Adjust SLOs or targets if needed

**Attendees**: Engineering team, SRE, Product

**Output**: Monthly SLO report with action items

### Quarterly SLO Adjustment

SLOs should evolve with the system:

- **Too easy** (always met with 90%+ error budget): Tighten targets
- **Too strict** (rarely met): Relax targets or invest in reliability
- **New features**: Define SLOs for new capabilities
- **Workload changes**: Adjust based on actual usage patterns

---

## Capacity Planning

### Traffic Growth Assumptions

- **Linear growth**: 20% quarter-over-quarter
- **Seasonal peaks**: 2x normal traffic during peaks
- **Provision for**: 3x current peak capacity

### Scaling Triggers

| Metric              | Threshold      | Action                            |
| ------------------- | -------------- | --------------------------------- |
| CPU utilization     | >70% sustained | Add instances                     |
| Memory utilization  | >80%           | Add instances or increase memory  |
| Cache hit rate      | <70%           | Increase cache size               |
| Storage latency p99 | >8ms           | Scale storage or optimize queries |
| Replication lag     | >200ms         | Add regions or increase bandwidth |

### Cost vs. Reliability Trade-offs

- **99.9% → 99.99%**: ~3-5x infrastructure cost
- **Cache size doubling**: ~10% cost increase, +5-10% hit rate
- **Additional regions**: +50% cost per region, -50ms latency for users

---

## Example: Working with SLOs

### Scenario 1: Latency SLO Violation

**Observation**: p99 latency increased from 5ms to 15ms

**Investigation**:

1. Check dashboard: Which endpoint is slow?
2. Query Prometheus: `histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m]))`
3. Examine traces: Identify slow component (storage, cache miss, evaluation)
4. Check recent changes: Recent deployment?

**Response**:

- If cache-related: Increase cache size or TTL
- If storage-related: Optimize queries or scale storage
- If evaluation-related: Optimize policy or add caching
- If deployment-related: Rollback and investigate

**Postmortem**: Document findings and preventive measures

### Scenario 2: Error Budget Exhausted

**Observation**: 99.9% availability target missed, 0% error budget remaining

**Action**:

1. **Immediate**: Freeze all non-critical deployments
2. **Investigate**: Root cause analysis of increased errors
3. **Fix**: Address underlying issue
4. **Validate**: Confirm SLO is back on track
5. **Resume**: Gradual return to normal operations

**Timeline**: Typically 1-3 days depending on complexity

---

## References

- [Google SRE Book - Service Level Objectives](https://sre.google/sre-book/service-level-objectives/)
- [Prometheus Alerting Best Practices](https://prometheus.io/docs/practices/alerting/)
- [Multi-window, Multi-burn-rate Alerts](https://sre.google/workbook/alerting-on-slos/)

---

## Revision History

| Date       | Version | Changes                 |
| ---------- | ------- | ----------------------- |
| 2025-01-15 | 1.0     | Initial SLO definitions |
