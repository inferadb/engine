# Memory Profiling and Leak Detection Guide

This guide covers tools and techniques for detecting memory leaks, profiling heap usage, and diagnosing memory-related issues in InferaDB.

## Table of Contents

- [Quick Start](#quick-start)
- [Memory Leak Tests](#memory-leak-tests)
- [Profiling Tools](#profiling-tools)
- [Interpreting Results](#interpreting-results)
- [Common Issues](#common-issues-and-solutions)
- [CI Integration](#ci-integration)

---

## Quick Start

### Run Short Memory Tests (CI-friendly)

```bash
# Run all memory leak tests (short versions)
cargo test --test memory_leak_tests

# Run specific test
cargo test --test memory_leak_tests test_no_memory_leak_in_authorization_checks
```

### Run Long-Running Stress Tests

```bash
# 24-hour authorization stress test
cargo test --test memory_leak_tests test_24h_authorization_stress -- --ignored --nocapture

# 24-hour mixed workload test
cargo test --test memory_leak_tests test_24h_mixed_workload -- --ignored --nocapture
```

### Quick Memory Profile

```bash
# Using valgrind (Linux)
valgrind --leak-check=full --show-leak-kinds=all \
    cargo test --test memory_leak_tests

# Using Instruments (macOS)
cargo instruments -t Allocations --test memory_leak_tests
```

---

## Memory Leak Tests

InferaDB includes comprehensive memory leak detection tests in `crates/infera-api/tests/memory_leak_tests.rs`.

### Test Categories

#### 1. Short-Running Tests (for CI)

These tests run quickly (<5 minutes) and are suitable for CI pipelines:

- `test_no_memory_leak_in_authorization_checks` - Tests 10,000 authorization checks
- `test_no_memory_leak_in_expand_operations` - Tests 1,000 expand operations
- `test_no_memory_leak_in_storage_operations` - Tests 5,000 write/read cycles
- `test_no_memory_leak_in_cache_eviction` - Tests cache eviction (20,000 checks)
- `test_no_memory_leak_under_concurrent_load` - Tests 10 concurrent workers
- `test_no_memory_leak_in_streaming` - Tests 500 stream create/consume cycles
- `test_no_connection_leaks` - Tests 5,000 operations for connection leaks

#### 2. Long-Running Tests (manual execution)

These tests are marked with `#[ignore]` and must be run explicitly:

- `test_24h_authorization_stress` - Runs authorization checks for 24 hours
- `test_24h_mixed_workload` - Runs mixed workload (70/20/10 split) for 24 hours

**Running ignored tests:**

```bash
cargo test --test memory_leak_tests test_24h_authorization_stress -- --ignored --nocapture
```

### What These Tests Detect

- **Unbounded memory growth**: Memory usage increasing without bound
- **Cache leaks**: Objects not being evicted from caches
- **Connection leaks**: Database/network connections not being released
- **Stream leaks**: Async streams not being properly cleaned up
- **Reference leaks**: Arc/Rc cycles preventing cleanup
- **Temporary allocation leaks**: Objects created during operations not being freed

---

## Profiling Tools

### Option 1: Valgrind (Linux)

**Best for:** Comprehensive leak detection and memory error diagnosis

**Installation:**

```bash
# Ubuntu/Debian
sudo apt-get install valgrind

# Fedora
sudo dnf install valgrind

# Arch
sudo pacman -S valgrind
```

**Usage:**

```bash
# Basic leak check
valgrind --leak-check=full cargo test --test memory_leak_tests

# Detailed leak check with all leak kinds
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
    cargo test --test memory_leak_tests

# Save output to file
valgrind --leak-check=full --log-file=valgrind.log \
    cargo test --test memory_leak_tests
```

**Interpreting output:**

```text
==12345== LEAK SUMMARY:
==12345==    definitely lost: 0 bytes in 0 blocks
==12345==    indirectly lost: 0 bytes in 0 blocks
==12345==      possibly lost: 0 bytes in 0 blocks
==12345==    still reachable: 8,192 bytes in 1 blocks
==12345==         suppressed: 0 bytes in 0 blocks
```

- **Definitely lost**: Real memory leaks - must fix
- **Indirectly lost**: Memory lost due to definitely lost blocks
- **Possibly lost**: Might be leaked or might be reachable
- **Still reachable**: Memory still referenced at exit (usually OK)

### Option 2: DHAT (Heap Profiler)

**Best for:** Detailed heap profiling with minimal overhead

**Installation:**

Add to `Cargo.toml`:

```toml
[dev-dependencies]
dhat = "0.3"
```

**Usage:**

1. Wrap your test with DHAT profiler:

```rust
use dhat::{Dhat, DhatAlloc};

#[global_allocator]
static ALLOCATOR: DhatAlloc = DhatAlloc;

#[tokio::test]
async fn test_with_dhat() {
    let _dhat = Dhat::start_heap_profiling();

    // Your test code here

    // DHAT output written to dhat-heap.json on drop
}
```

1. Run test:

```bash
cargo test test_with_dhat
```

1. View results:

```bash
# Install dh_view.html from DHAT repository
# Open dhat-heap.json in dh_view.html
```

**Metrics provided:**

- Total bytes allocated
- Total blocks allocated
- Peak memory usage
- Allocation hot spots

### Option 3: Heaptrack (Linux)

**Best for:** Real-time heap profiling with GUI visualization

**Installation:**

```bash
# Ubuntu/Debian
sudo apt-get install heaptrack heaptrack-gui

# Fedora
sudo dnf install heaptrack

# Arch
sudo pacman -S heaptrack
```

**Usage:**

```bash
# Profile a test run
heaptrack cargo test --test memory_leak_tests

# Analyze results with GUI
heaptrack_gui heaptrack.cargo.12345.gz
```

**Features:**

- Real-time memory usage graphs
- Flamegraph of allocation call stacks
- Leak detection
- Temporary allocation analysis

### Option 4: cargo-instruments (macOS)

**Best for:** Native macOS profiling with Instruments.app integration

**Installation:**

```bash
cargo install cargo-instruments
```

**Usage:**

```bash
# Allocations template (memory profiling)
cargo instruments -t Allocations --test memory_leak_tests

# Leaks template (leak detection)
cargo instruments -t Leaks --test memory_leak_tests

# Time Profiler (CPU profiling)
cargo instruments -t "Time Profiler" --test memory_leak_tests
```

**Features:**

- Native Instruments.app integration
- Beautiful visualizations
- Multiple profiling templates
- Low overhead

### Option 5: massif (Valgrind heap profiler)

**Best for:** Heap profiling over time

**Usage:**

```bash
# Run with massif
valgrind --tool=massif cargo test --test memory_leak_tests

# Visualize results
ms_print massif.out.12345

# Or use massif-visualizer (GUI)
massif-visualizer massif.out.12345
```

**Output shows:**

- Heap usage over time
- Peak memory usage
- Allocation sites for peak memory

---

## Interpreting Results

### Signs of Memory Leaks

1. **Unbounded Growth**

   ```text
   Iteration 1000: RSS = 50 MB
   Iteration 2000: RSS = 100 MB
   Iteration 3000: RSS = 150 MB  <-- Linear growth!
   ```

   **Action:** Investigate recent operations for unreleased resources

2. **Valgrind "definitely lost"**

   ```text
   ==12345== 1,024 bytes in 1 blocks are definitely lost
   ==12345==    at 0x...: malloc
   ==12345==    by 0x...: alloc::vec::Vec::push
   ```

   **Action:** Fix the allocation site shown in stack trace

3. **Heaptrack plateau that doesn't drop**

   Memory usage plateaus high and never drops, even during idle periods.

   **Action:** Check for global caches or static data structures

### Normal Behavior

1. **Sawtooth Pattern**

   Memory grows then drops (GC/cleanup cycles) - this is normal

2. **Initial Spike**

   Memory usage high at start, then stabilizes - normal warmup

3. **"Still reachable" in Valgrind**

   Memory reachable at program exit - usually OK for short-lived programs

---

## Common Issues and Solutions

### Issue: Cache Growing Unbounded

**Symptoms:**

- Memory increases linearly with operations
- No plateau even after warmup

**Diagnosis:**

```rust
// Check cache has bounded size
let cache = AuthCache::new(10_000, Duration::from_secs(300));
```

**Solution:**

- Ensure cache has maximum capacity
- Verify eviction policy is working
- Check for cache keys that prevent eviction

### Issue: Arc Reference Cycles

**Symptoms:**

- Valgrind shows "possibly lost" or "still reachable"
- Objects not dropped when expected

**Diagnosis:**

```rust
// Look for circular Arc references
struct Node {
    parent: Arc<Node>,  // Creates cycle!
    child: Arc<Node>,
}
```

**Solution:**

- Use `Weak<T>` for back-references
- Break cycles explicitly with `drop()`
- Avoid bidirectional Arc references

### Issue: Async Task Leaks

**Symptoms:**

- Tokio tasks never complete
- Memory grows with each operation

**Diagnosis:**

```rust
// Check for spawned tasks that don't finish
tokio::spawn(async {
    loop {  // Never exits!
        // ...
    }
});
```

**Solution:**

- Ensure all spawned tasks have termination conditions
- Use `JoinHandle` and await or abort tasks
- Set timeouts on long-running operations

### Issue: Connection Pool Exhaustion

**Symptoms:**

- Operations slow down over time
- Eventually get "connection pool exhausted" errors

**Diagnosis:**

```rust
// Check connections are returned to pool
let conn = pool.get().await?;
// ... use conn ...
// drop(conn);  // Returns to pool
```

**Solution:**

- Ensure connections are properly dropped
- Check connection timeout settings
- Verify connection pool max size is appropriate

---

## CI Integration

### GitHub Actions Example

```yaml
name: Memory Leak Detection

on:
  schedule:
    - cron: "0 2 * * 0" # Weekly on Sunday at 2 AM
  workflow_dispatch:

jobs:
  memory-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install Valgrind
        run: sudo apt-get update && sudo apt-get install -y valgrind

      - name: Run memory leak tests
        run: |
          cargo test --test memory_leak_tests

      - name: Run with Valgrind
        run: |
          valgrind --leak-check=full --error-exitcode=1 \
            --log-file=valgrind.log \
            cargo test --test memory_leak_tests

      - name: Upload Valgrind results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: valgrind-logs
          path: valgrind.log

      - name: Check for leaks
        run: |
          if grep -q "definitely lost" valgrind.log; then
            echo "Memory leaks detected!"
            exit 1
          fi
```

### Long-Running Test Schedule

For 24-hour tests, use a dedicated runner:

```yaml
name: Long-Running Memory Tests

on:
  schedule:
    - cron: "0 0 1 * *" # Monthly on the 1st
  workflow_dispatch:

jobs:
  long-running-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 1500 # 25 hours
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Run 24-hour stress test
        run: |
          cargo test --test memory_leak_tests test_24h_authorization_stress \
            -- --ignored --nocapture | tee stress-test.log

      - name: Analyze results
        run: |
          # Extract final iteration count
          grep "Completed" stress-test.log

      - name: Upload logs
        uses: actions/upload-artifact@v3
        with:
          name: stress-test-logs
          path: stress-test.log
```

---

## Best Practices

1. **Run short tests in CI**: Include quick memory tests in every PR
2. **Run long tests periodically**: Schedule 24-hour tests weekly/monthly
3. **Profile before releases**: Always profile before major releases
4. **Monitor production**: Use runtime metrics to detect leaks in production
5. **Test with realistic data**: Use production-like data volumes
6. **Test concurrency**: Always test with concurrent load
7. **Check connection pools**: Verify connections are released
8. **Review cache policies**: Ensure caches have bounded growth

---

## Resources

- [Valgrind Manual](https://valgrind.org/docs/manual/manual.html)
- [DHAT Documentation](https://docs.rs/dhat/latest/dhat/)
- [Heaptrack Documentation](https://github.com/KDE/heaptrack)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Tokio Console](https://github.com/tokio-rs/console) - Async runtime monitoring

---

## Troubleshooting

### Valgrind shows false positives

Some Rust standard library code may appear to leak. Use suppression files:

```bash
valgrind --suppressions=rust.supp cargo test
```

Create `rust.supp`:

```text
{
   rust_std_lib
   Memcheck:Leak
   ...
   obj:*/libstd-*.so
}
```

### Tests pass but production leaks

- Production workload may differ from tests
- Check for operations not covered by tests
- Add tests that match production patterns
- Monitor production metrics

### Profiler overhead too high

- Use sampling profilers instead of instrumentation
- Profile shorter test runs
- Use release builds: `cargo test --release`

---

**Last Updated:** 2025-11-03
**See Also:** `BENCHMARKS.md`, `PLAN.md` Task 3.4.4
