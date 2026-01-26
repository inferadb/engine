# Testing Quick Start

Run tests efficiently with InferaDB's tiered test system.

## Quick Commands

```bash
# Fast tests (~15s) - for quick validation
just test-fast

# Standard tests (~30s) - for local development
just test

# Full tests (~5min) - for comprehensive validation
just test-full
```

## Using cargo directly

```bash
# Fast tier (PR checks)
PROPTEST_CASES=10 cargo nextest run --profile fast

# Standard tier (local dev)
cargo nextest run --profile ci

# Full tier (nightly/release)
PROPTEST_CASES=500 cargo nextest run --profile full --features test-full --run-ignored all
```

## Running Specific Tests

```bash
# Single test
cargo test test_check_allow

# Tests matching pattern
cargo test check_

# Specific package
cargo test --package inferadb-engine-core

# With output
cargo test -- --nocapture
```

## Test Categories

| Category | Location | Run |
|----------|----------|-----|
| Unit tests | `src/**/*.rs` | `cargo test --lib` |
| Integration | `tests/*.rs` | `cargo test --test '*'` |
| Property | `#[cfg(test)] mod proptests` | `cargo test prop_` |
| Fuzz | `tests/*_fuzz.rs` | `cargo test fuzz_` |
| Security | `tests/sandbox_security.rs` | `cargo test --test sandbox_security` |
| Load | `tests/performance_load.rs` | `cargo test -- --ignored` |

## Coverage

```bash
cargo llvm-cov --workspace --html
open target/llvm-cov/html/index.html
```

## Performance Analysis

```bash
# Analyze test times
python3 scripts/analyze-test-times.py

# Update baseline after intentional changes
python3 scripts/analyze-test-times.py --update-baseline
```

## More Information

See [docs/guides/testing.md](docs/guides/testing.md) for comprehensive documentation.
