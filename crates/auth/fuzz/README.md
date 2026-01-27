# Fuzz Testing for InferaDB Authentication

This directory contains fuzz tests for the InferaDB authentication system using `cargo-fuzz` and `libFuzzer`.

## Prerequisites

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Ensure you're using nightly Rust (required for cargo-fuzz)
rustup install nightly
```

## Running Fuzz Tests

### JWT Decoding Fuzzer

Tests JWT header and claims decoding with malformed input:

```bash
# Run for 5 minutes
cargo +nightly fuzz run jwt_decode -- -max_total_time=300

# Run until crash or manual stop
cargo +nightly fuzz run jwt_decode

# Run with custom timeout and memory limit
cargo +nightly fuzz run jwt_decode -- -max_total_time=600 -rss_limit_mb=2048
```

### JWT Validation Fuzzer

Tests timestamp and algorithm validation with random values:

```bash
# Run for 5 minutes
cargo +nightly fuzz run jwt_validation -- -max_total_time=300

# Run with verbose output
cargo +nightly fuzz run jwt_validation -- -max_total_time=300 -verbosity=2
```

### Bearer Token Extraction Fuzzer

Tests HTTP Authorization header parsing with malformed input:

```bash
# Run for 5 minutes
cargo +nightly fuzz run bearer_extraction -- -max_total_time=300
```

## Analyzing Results

### Check for Crashes

If a fuzzer finds a crash, it will save the input in `fuzz/artifacts/`:

```bash
# List crash artifacts
ls -la fuzz/artifacts/jwt_decode/

# Reproduce a crash
cargo +nightly fuzz run jwt_decode fuzz/artifacts/jwt_decode/crash-abc123
```

### Code Coverage

Check which code paths are being exercised:

```bash
# Generate coverage report
cargo +nightly fuzz coverage jwt_decode

# View coverage with llvm-cov
cargo +nightly fuzz coverage --html jwt_decode
open fuzz/coverage/jwt_decode/index.html
```

### Corpus Management

The fuzzer builds a corpus of interesting inputs over time:

```bash
# View corpus inputs
ls -la fuzz/corpus/jwt_decode/

# Minimize the corpus (remove redundant inputs)
cargo +nightly fuzz cmin jwt_decode

# Minimize test cases (make them shorter)
cargo +nightly fuzz tmin jwt_decode fuzz/corpus/jwt_decode/input-file
```

## Continuous Fuzzing

### Run All Fuzzers

```bash
#!/bin/bash
# run-all-fuzzers.sh

FUZZ_TIME=300  # 5 minutes per fuzzer

echo "Running jwt_decode fuzzer..."
cargo +nightly fuzz run jwt_decode -- -max_total_time=$FUZZ_TIME

echo "Running jwt_validation fuzzer..."
cargo +nightly fuzz run jwt_validation -- -max_total_time=$FUZZ_TIME

echo "Running bearer_extraction fuzzer..."
cargo +nightly fuzz run bearer_extraction -- -max_total_time=$FUZZ_TIME

echo "All fuzzers completed!"
```

### CI Integration

Add to `.github/workflows/fuzz.yml`:

```yaml
name: Fuzz Tests

on:
    schedule:
        - cron: "0 2 * * *" # Run daily at 2 AM
    workflow_dispatch:

jobs:
    fuzz:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v3

            - name: Install Rust nightly
              uses: actions-rs/toolchain@v1
              with:
                  toolchain: nightly
                  override: true

            - name: Install cargo-fuzz
              run: cargo install cargo-fuzz

            - name: Run fuzz tests
              run: |
                  cd crates/inferadb-engine-auth
                  cargo +nightly fuzz run jwt_decode -- -max_total_time=600 -rss_limit_mb=2048
                  cargo +nightly fuzz run jwt_validation -- -max_total_time=600 -rss_limit_mb=2048
                  cargo +nightly fuzz run bearer_extraction -- -max_total_time=600 -rss_limit_mb=2048

            - name: Upload artifacts
              if: failure()
              uses: actions/upload-artifact@v3
              with:
                  name: fuzz-artifacts
                  path: crates/inferadb-engine-auth/fuzz/artifacts/
```

## Expected Behavior

All fuzzers should:

- ✅ **Never panic**: All code paths return `Result`, never panic
- ✅ **Handle malformed input gracefully**: Return appropriate errors
- ✅ **Not leak memory**: No memory leaks on invalid input
- ✅ **Complete within time limit**: No infinite loops

### Acceptable Outcomes

- `InvalidTokenFormat` error for malformed JWTs
- `MissingClaim` error for missing required claims
- `UnsupportedAlgorithm` error for forbidden algorithms
- `TokenExpired` error for expired tokens

### Unacceptable Outcomes

- ❌ **Panics**: Code should never panic
- ❌ **Crashes**: Segmentation faults, aborts
- ❌ **Hangs**: Infinite loops or excessive execution time
- ❌ **Memory leaks**: Growing memory usage over time

## Debugging Crashes

If a fuzzer discovers a crash:

1. **Reproduce locally**:

    ```bash
    cargo +nightly fuzz run jwt_decode fuzz/artifacts/jwt_decode/crash-abc123
    ```

2. **Debug with lldb/gdb**:

    ```bash
    rust-lldb target/x86_64-unknown-linux-gnu/release/jwt_decode fuzz/artifacts/jwt_decode/crash-abc123
    ```

3. **Analyze the input**:

    ```bash
    # View raw bytes
    hexdump -C fuzz/artifacts/jwt_decode/crash-abc123

    # View as string (if valid UTF-8)
    cat fuzz/artifacts/jwt_decode/crash-abc123
    ```

4. **Write a regression test**:

    ```rust
    #[test]
    fn test_crash_abc123() {
        let input = include_bytes!("../fuzz/artifacts/jwt_decode/crash-abc123");
        let result = decode_jwt_header(std::str::from_utf8(input).unwrap());
        assert!(result.is_err());  // Should return error, not panic
    }
    ```

## Performance Tips

### Parallel Fuzzing

Run multiple fuzzer instances in parallel:

```bash
# Run 4 parallel instances
for i in {1..4}; do
    cargo +nightly fuzz run jwt_decode -- -max_total_time=3600 -jobs=1 &
done
wait
```

### Faster Fuzzing

```bash
# Use more aggressive fuzzing options
cargo +nightly fuzz run jwt_decode -- \
    -max_total_time=600 \
    -rss_limit_mb=4096 \
    -timeout=10 \
    -use_value_profile=1
```

## Resources

- [cargo-fuzz book](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [Rust Fuzz Project](https://github.com/rust-fuzz)
- [OWASP Fuzzing Guide](https://owasp.org/www-community/Fuzzing)

## Maintenance

- **Weekly**: Run fuzzers for 1 hour each
- **Before releases**: Run fuzzers for 4-8 hours
- **After major changes**: Run relevant fuzzers
- **Quarterly**: Review and update fuzz targets
