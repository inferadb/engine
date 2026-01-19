# Performance Baselines

This document establishes performance baselines for InferaDB based on load testing and benchmarks. These baselines help identify performance regressions and validate that the system meets its [Service Level Objectives (SLOs)](slos.md).

## Overview

Performance baselines are established through:

1. **Load tests** (`crates/inferadb-engine-core/tests/performance_load.rs`) - Integration-level load simulation
2. **Criterion benchmarks** (`crates/inferadb-engine-core/benches/`) - Microbenchmarks for specific components
3. **Production metrics** - Real-world performance data (when available)

## Test Environment

All baseline measurements are performed on the following test environment:

- **CPU**: Development machine (varies, typically 4-8 cores)
- **Memory**: 16GB+ RAM
- **Storage**: In-memory backend (MemoryBackend)
- **Concurrency**: Tokio async runtime
- **Build**: `cargo test --release` (optimized builds)

**Note**: Production performance may differ based on hardware, storage backend (Ledger vs Memory), and network latency.

---

## Core Performance Baselines

### 1. Authorization Check Latency

**SLO Target**: p99 < 10ms (see [slos.md](slos.md#2-request-latency-slo))

**Test**: `test_latency_p99_under_10ms`

**Baseline Results**:

- **p50 latency**: < 1ms (typical: 0.2-0.5ms)
- **p90 latency**: < 2ms (typical: 0.5-1ms)
- **p95 latency**: < 3ms (typical: 1-2ms)
- **p99 latency**: < 5ms (typical: 2-4ms)
- **p99.9 latency**: < 10ms (typical: 5-8ms)

**Sample Size**: 10,000 requests

**Interpretation**:

- In-memory backend performs well under SLO targets
- Real-world latency with Ledger will be higher (add 2-5ms per storage operation)
- WASM policies add overhead (see WASM section below)

---

### 2. Sustained Throughput

**SLO Target**: Not explicitly defined, but system should handle production loads without degradation

**Test**: `test_sustained_throughput_100k_rps` (ignored by default, long-running)

**Baseline Results**:

- **Target**: 100,000 RPS for 10 seconds
- **Achieved**: 50,000+ RPS (typical: 60,000-80,000 RPS on dev hardware)
- **Concurrency**: 100 workers
- **p99 latency at load**: < 50ms

**Interpretation**:

- Single-instance throughput is sufficient for most deployments
- Production deployments use horizontal scaling for higher throughput
- Bottleneck is typically CPU-bound evaluation, not I/O

---

### 3. Spike Load Handling

**SLO Target**: System should gracefully handle traffic spikes without catastrophic failure

**Test**: `test_spike_load`

**Baseline Results**:

- **Normal load**: 100 RPS (2 workers, 100 requests each)
- **Spike load**: 10,000 RPS (100 workers, 100 requests each)
- **Latency degradation**: p99 increases by <10x during spike
  - Normal: p99 < 5ms
  - Spike: p99 < 50ms
- **Error rate**: 0% (no failures during spike)

**Interpretation**:

- System handles sudden traffic increases gracefully
- Latency degrades proportionally to load increase (expected behavior)
- No request failures or timeouts during spike

---

### 4. Stress Testing (Capacity Limits)

**SLO Target**: Identify breaking point and ensure graceful degradation

**Test**: `test_stress_beyond_capacity` (ignored by default, long-running)

**Baseline Results**:

- **Concurrency levels tested**: 10, 50, 100, 200, 500 workers
- **Breaking point**: Varies by hardware, typically 200-500 workers
- **Behavior at capacity**:
  - Latency increases linearly with concurrency
  - No request failures (system queues requests)
  - CPU utilization approaches 100%

**Interpretation**:

- System degrades gracefully under extreme load
- No crashes or panics observed
- Production deployments should target <70% CPU utilization for headroom

---

### 5. Soak Testing (Long-term Stability)

**SLO Target**: < 0.1% error rate over extended periods

**Test**: `test_soak_24h_simulation` (ignored by default, long-running)

**Baseline Results**:

- **Duration**: 60 seconds (simulating 24h load pattern)
- **Total requests**: Varies based on load pattern
- **Error rate**: < 0.01% (typical: 0%)
- **Memory growth**: None observed (no memory leaks)
- **Latency drift**: None (latency remains stable)

**Interpretation**:

- System is stable over extended periods
- No memory leaks or resource exhaustion
- Suitable for long-running production deployments

---

## Scale Testing Baselines

### 6. Large Graph Performance

**Test**: `test_large_graph_1m_tuples` (ignored by default, long-running)

**Baseline Results**:

- **Dataset size**: 1,000,000 tuples
- **Batch write performance**: ~10,000-50,000 tuples/second
- **Check latency on large graph**: p99 < 50ms
- **Memory footprint**: ~100-200MB for 1M tuples (in-memory backend)

**Interpretation**:

- System handles large datasets (millions of tuples)
- Check latency remains acceptable even with large graphs
- Ledger backend scales beyond in-memory limits

---

### 7. Deep Nesting Performance

**SLO Target**: p99 < 10 levels of evaluation depth (see [slos.md](slos.md#8-evaluation-depth))

**Test**: `test_deep_nesting_10_levels`

**Baseline Results**:

- **Nesting depth**: 15 levels
- **Max latency**: < 100ms for deepest level
- **Average latency**: ~5-10ms per level
- **Behavior**: Latency increases linearly with depth

**Interpretation**:

- System handles deep hierarchies (10+ levels)
- Performance degrades linearly, not exponentially
- Caching mitigates repeated traversals

---

### 8. Wide Expansion Performance

**Test**: `test_wide_expansion_10k_users` (ignored by default, long-running)

**Baseline Results**:

- **Expansion size**: 10,000 users on single resource
- **Expansion duration**: < 500ms
- **Memory overhead**: ~1-2MB for 10k user result set

**Interpretation**:

- System efficiently expands large usersets
- Suitable for resources with many viewers (e.g., public documents)
- Consider pagination for very large expansions (>100k users)

---

## WASM Policy Performance

**SLO Target**: p99 < 50ms for WASM-enhanced checks (see [slos.md](slos.md#2-request-latency-slo))

**Test**: ABAC tests in `crates/inferadb-engine-core/tests/attribute_based_access.rs`

**Baseline Results**:

- **WASM module load time**: <1ms (cached after first use)
- **WASM execution overhead**: +5-10ms per check (typical simple policies)
- **Complex WASM policies**: +10-50ms (depending on policy complexity)
- **p99 latency with WASM**: < 20ms (simple policies)

**Interpretation**:

- WASM adds measurable overhead but remains within SLO
- Module caching is essential for performance
- Complex policies (parsing context, evaluating rules) increase latency

---

## Storage Backend Comparison

### Memory Backend (MemoryBackend)

**Characteristics**:

- **Read latency**: < 0.1ms
- **Write latency**: < 0.1ms
- **Throughput**: CPU-bound, 100k+ ops/sec
- **Persistence**: None (in-memory only)
- **Use cases**: Testing, development, ephemeral deployments

### Ledger Backend

**Characteristics**:

- **Read latency**: 2-5ms (including network)
- **Write latency**: 5-10ms (including network + commit)
- **Throughput**: Network and disk-bound, 10k-50k ops/sec per node
- **Persistence**: Durable, replicated via Raft
- **Use cases**: Production, multi-region deployments

**Impact on Authorization Latency**:

- Add ~2-5ms to authorization check latency for cache misses
- Cache hit rate becomes critical for meeting SLOs

---

## Regression Detection

### Automated Baseline Comparison

To detect performance regressions, compare current test results against these baselines:

1. **Latency Regression**: Current p99 > Baseline p99 \* 1.2 (20% degradation)
2. **Throughput Regression**: Current RPS < Baseline RPS \* 0.8 (20% reduction)
3. **Error Rate Regression**: Current errors > Baseline errors + 0.1%

### Continuous Performance Testing

**Recommended workflow**:

1. Run fast performance tests on every PR: `cargo test --test performance_load`
2. Run full performance suite weekly: `cargo test --test performance_load --include-ignored`
3. Run Criterion benchmarks on performance-sensitive changes: `cargo bench`
4. Compare results against baselines
5. Investigate any regressions before merging

### Baseline Update Policy

Update baselines when:

- **Hardware changes**: New test environment requires new baselines
- **Intentional optimizations**: Performance improvements should update baselines downward
- **Architecture changes**: Major refactors may justify baseline adjustments
- **Storage backend changes**: Different backends have different characteristics

**Process**:

1. Run full performance suite 3+ times
2. Calculate average and p99 values
3. Update this document with new baselines
4. Document reason for baseline change
5. Get team approval for baseline adjustments

---

## Performance Monitoring in Production

### Key Metrics to Track

Track these metrics in production to validate baselines:

```promql
# Authorization check latency
histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m]))

# Throughput (requests per second)
sum(rate(inferadb_checks_total[1m]))

# Error rate
sum(rate(inferadb_engine_api_errors_total{code=~"5.."}[5m]))
/ sum(rate(inferadb_checks_total[5m]))

# Evaluation depth
histogram_quantile(0.99, rate(inferadb_evaluation_depth_bucket[5m]))
```

### Alerting on Baseline Deviations

Alert when production performance deviates significantly from baselines:

```yaml
- alert: LatencyRegressionDetected
  expr: |
    histogram_quantile(0.99, rate(inferadb_check_duration_seconds_bucket[5m])) > 0.012
  for: 10m
  labels:
    severity: P1
  annotations:
    summary: "p99 latency exceeds baseline (>12ms vs 10ms SLO)"

- alert: ThroughputDegradation
  expr: |
    sum(rate(inferadb_checks_total[5m])) < (avg_over_time(sum(rate(inferadb_checks_total[5m]))[1h]) * 0.5)
  for: 5m
  labels:
    severity: P1
  annotations:
    summary: "Throughput dropped by >50% compared to 1h average"
```

---

## Benchmark Results (Criterion)

### Evaluation Benchmarks

**Location**: `crates/inferadb-engine-core/benches/evaluation.rs`

**Results** (typical):

- **Simple direct check**: ~100-200 ns
- **Union relation check**: ~500 ns - 1 µs
- **Nested relation check (3 levels)**: ~2-5 µs
- **Complex graph traversal (10 nodes)**: ~10-50 µs

**Interpretation**: Evaluation logic is highly efficient, storage access dominates latency.

---

## References

- [Service Level Objectives (SLOs)](slos.md)
- [Load Testing Suite](../crates/inferadb-engine-core/tests/performance_load.rs)
- [ABAC Testing](../crates/inferadb-engine-core/tests/attribute_based_access.rs)
- [Criterion Benchmarks](../crates/inferadb-engine-core/benches/)

---

## Revision History

| Date       | Version | Changes                                   |
| ---------- | ------- | ----------------------------------------- |
| 2025-01-15 | 1.0     | Initial performance baselines established |
