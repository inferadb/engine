# InferaDB Benchmarking Guide

This document describes the performance benchmarking infrastructure for InferaDB, including how to run benchmarks, interpret results, and detect performance regressions.

## Overview

InferaDB uses [Criterion.rs](https://github.com/bheisler/criterion.rs) for performance benchmarking. Benchmarks are organized into two main suites:

1. **Core Evaluator Benchmarks** (`crates/inferadb-engine-core/benches/evaluator.rs`) - Tests core authorization engine performance
2. **API Throughput Benchmarks** (`crates/inferadb-engine-api/benches/api_throughput.rs`) - Tests end-to-end API performance

## Baseline Performance Metrics

These metrics were established on 2025-11-03 and serve as the regression detection baseline.

### Core Evaluator Performance

| Benchmark                       | Latency | Throughput    | Description                         |
| ------------------------------- | ------- | ------------- | ----------------------------------- |
| `direct_check_allow`            | 186 ns  | ~5.4M ops/sec | Direct relationship check (allowed) |
| `direct_check_deny`             | 182 ns  | ~5.5M ops/sec | Direct relationship check (denied)  |
| `union_check_allow`             | 179 ns  | ~5.6M ops/sec | Union expression evaluation         |
| `complex_check_with_trace`      | 3.7 µs  | ~270K ops/sec | Nested hierarchy with trace         |
| `expand_simple`                 | 346 ns  | ~2.9M ops/sec | Simple relationship expansion       |
| `expand_complex`                | 964 ns  | ~1.0M ops/sec | Complex union expansion             |
| `expand_parallel_4_branches`    | 8.7 µs  | ~115K ops/sec | 4-way parallel union (100 users)    |
| `expand_parallel_intersection`  | 6.7 µs  | ~149K ops/sec | 3-way parallel intersection         |
| `expand_with_cache_hit`         | 3.8 µs  | ~263K ops/sec | Cached expansion result             |
| `check_with_1000_relationships` | 188 ns  | ~5.3M ops/sec | Check with large dataset            |

**Key Insights:**

- Simple authorization checks complete in **<200 nanoseconds**
- Throughput exceeds **5 million operations per second** for direct checks
- Cache provides minimal benefit for simple checks (already extremely fast)
- Complex nested evaluations remain under 10 microseconds

### API Throughput Performance

| Benchmark                | Latency        | Throughput    | Target  | Status                  |
| ------------------------ | -------------- | ------------- | ------- | ----------------------- |
| `authorization_check/*`  | ~201 ns        | ~4.9M ops/sec | 10K RPS | ✅ **490x over target** |
| `relationship_write/1`   | 260 ns         | 3.8M ops/sec  | -       | ✅                      |
| `relationship_write/10`  | 1.5 µs         | 6.6M ops/sec  | -       | ✅                      |
| `relationship_write/50`  | 6.6 µs         | 7.5M ops/sec  | -       | ✅                      |
| `relationship_write/100` | 13.4 µs        | 7.4M ops/sec  | -       | ✅                      |
| `expand_viewer`          | 624 ns         | 1.6M ops/sec  | -       | ✅                      |
| `list_relationships/*`   | ~44-45 µs      | 220K-11M/sec  | -       | ✅                      |
| `mixed_workload`         | 31 µs / 10 ops | 322K ops/sec  | -       | ✅                      |
| `cache_hit`              | 185 ns         | -             | -       | ✅                      |
| `cache_miss`             | 3.8 µs         | -             | -       | ✅                      |

**Key Insights:**

- Authorization checks are **490x faster** than the 10,000 RPS target
- Cache provides **21x speedup** (185 ns vs 3.8 µs)
- Write batching scales linearly up to 100 relationships
- Mixed workload (70% read, 20% write, 10% expand) achieves 322K ops/sec

## Running Benchmarks

### Run All Benchmarks

```bash
# Run all benchmarks in the workspace
cargo bench --workspace

# Run with specific number of samples (default: 100)
cargo bench --workspace -- --sample-size 1000
```

### Run Specific Benchmark Suites

```bash
# Core evaluator benchmarks only
cargo bench --package inferadb-engine-core --bench evaluator

# API throughput benchmarks only
cargo bench --package inferadb-engine-api --bench api_throughput
```

### Run Individual Benchmarks

```bash
# Run a specific benchmark by name
cargo bench --bench evaluator -- direct_check_allow

# Run all authorization check variants
cargo bench --bench api_throughput -- authorization_check
```

## Performance Regression Detection

Criterion automatically tracks performance over time and detects regressions.

### How It Works

1. **First Run**: Criterion saves baseline results to `target/criterion/<benchmark_name>/base/`
2. **Subsequent Runs**: Criterion compares new results against the baseline
3. **Change Detection**: Reports performance changes with statistical significance

### Reading Criterion Output

Criterion reports changes in the following format:

```text
authorization_check/1_docs
                        time:   [200.76 ns 201.56 ns 202.56 ns]
                        change: [-2.1% +0.5% +3.2%] (p = 0.15 > 0.05)
                        No change in performance detected.
```

**Interpretation:**

- `time: [low med high]` - 95% confidence interval for the median
- `change: [low med high]` - Performance change vs baseline
- `p = X` - Statistical significance (p < 0.05 indicates significant change)
- Status message indicates if regression/improvement was detected

### Regression Thresholds

Per PLAN.md requirements, we monitor for regressions **>10%**.

**Action Required When:**

- Performance degrades by >10% with p < 0.05
- Multiple benchmarks show smaller regressions (trend)
- Cache effectiveness drops below 15x speedup

### Comparing Specific Baselines

```bash
# Save current results as a named baseline
cargo bench --bench evaluator -- --save-baseline my-baseline

# Compare against a specific baseline
cargo bench --bench evaluator -- --baseline my-baseline

# List available baselines
ls target/criterion/direct_check_allow/
```

### Viewing Historical Results

Criterion generates HTML reports with graphs:

```bash
# Open the report for a specific benchmark
open target/criterion/direct_check_allow/report/index.html

# View the full report index
open target/criterion/report/index.html
```

## Continuous Integration

### Current Status

Benchmarks are **not yet integrated into CI** but are ready for integration.

### Recommended CI Approach

**Option 1: Scheduled Benchmark Runs**

- Run benchmarks nightly on dedicated hardware
- Compare against saved baselines
- Alert on regressions >10%
- Store results for trend analysis

**Option 2: PR Benchmark Checks**

- Run benchmarks on PRs that touch performance-critical paths
- Compare against main branch baseline
- Block merge if regression >10% without justification
- Requires consistent CI runner hardware for accuracy

**Option 3: Hybrid Approach** (Recommended)

- Nightly full benchmark runs on dedicated hardware
- PR checks only run fast benchmarks (<30s total)
- Manual trigger for full benchmark suite on PRs

### Example GitHub Actions Workflow

```yaml
name: Benchmarks

on:
  schedule:
    - cron: "0 2 * * *" # 2 AM daily
  workflow_dispatch: # Manual trigger

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Run benchmarks
        run: cargo bench --workspace

      - name: Store results
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: "cargo"
          output-file-path: target/criterion/*/new/estimates.json
          alert-threshold: "110%" # Alert on 10% regression
          fail-on-alert: true
```

## Benchmark Implementation Details

### Core Evaluator Benchmarks

Located in `crates/inferadb-engine-core/benches/evaluator.rs`:

- **Direct checks**: Test simple relationship lookups
- **Union checks**: Test OR logic across multiple branches
- **Complex checks**: Test nested hierarchies with parent traversal
- **Expand operations**: Test subject enumeration with various complexity
- **Parallel operations**: Test concurrent branch evaluation
- **Cache effectiveness**: Test cache hit vs miss performance
- **Scale tests**: Test performance with 1000+ relationships

### API Throughput Benchmarks

Located in `crates/inferadb-engine-api/benches/api_throughput.rs`:

- **Authorization checks**: Vary dataset size (1, 10, 100, 1000 docs)
- **Relationship writes**: Vary batch size (1, 10, 50, 100)
- **Expand operations**: Test subject enumeration
- **List operations**: Vary result limit (10, 50, 100, 500)
- **Mixed workload**: Realistic usage pattern (70/20/10 split)
- **Cache effectiveness**: Direct comparison of hit vs miss

### Adding New Benchmarks

Follow the existing pattern in benchmark files:

```rust
fn bench_my_operation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let state = rt.block_on(setup_test_state());

    let mut group = c.benchmark_group("my_operation");
    group.throughput(Throughput::Elements(1));

    group.bench_function("my_test_case", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(state.perform_operation().await.unwrap())
        });
    });

    group.finish();
}

criterion_group!(benches, bench_my_operation);
criterion_main!(benches);
```

**Best Practices:**

1. Use `black_box()` to prevent optimizer from eliminating work
2. Set appropriate `Throughput` for meaningful metrics
3. Warm up caches if testing steady-state performance
4. Use realistic test data representative of production
5. Group related benchmarks together
6. Add comments explaining what is being measured

## Troubleshooting

### Noisy Results

If benchmarks show high variance:

1. Close other applications
2. Disable CPU frequency scaling: `sudo cpupower frequency-set --governor performance`
3. Increase sample size: `--sample-size 500`
4. Run longer warmup: criterion does this automatically

### Baseline Drift

If all benchmarks show consistent small changes:

1. Check for system-wide changes (OS updates, background services)
2. Verify CPU frequency scaling is disabled
3. Consider re-establishing baseline on stable system
4. Use named baselines to track across system changes

### Benchmark Compilation Failures

If benchmarks fail to compile after API changes:

1. Update request/response types to match current API
2. Check method signatures in core evaluator
3. Ensure vault scoping is correct
4. Run `cargo check --benches` to verify

## Resources

- [Criterion.rs User Guide](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [InferaDB Architecture](./CLAUDE.md)
- [Development Plan](./PLAN.md)

## Performance Targets

| Metric               | Target    | Current       | Status              |
| -------------------- | --------- | ------------- | ------------------- |
| Authorization RPS    | 10,000    | 4,900,000     | ✅ 490x over        |
| P99 Latency (simple) | <1ms      | <1µs          | ✅ 1000x better     |
| Cache Hit Ratio      | >80%      | N/A           | Track in production |
| Write Throughput     | 1,000/sec | 3,800,000/sec | ✅ 3800x over       |

## Next Steps

1. ✅ Establish baseline metrics (2025-11-03)
2. ✅ Document benchmark usage
3. ⏳ Integrate into CI pipeline (planned)
4. ⏳ Set up alerting for regressions >10% (planned)
5. ⏳ Add memory profiling benchmarks (Task 3.4.4)
6. ⏳ Add flamegraph generation for hot path analysis (future)
