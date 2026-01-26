# InferaDB Engine Justfile
# Run `just --list` to see available recipes

# Default recipe: run standard tests
default: test

# =============================================================================
# Test Tiers
# =============================================================================

# Run fast tests (PR checks, pre-commit)
# - 10 proptest cases
# - Fail-fast enabled
# - ~15 seconds
test-fast:
    PROPTEST_CASES=10 cargo nextest run --profile fast --features test-fast

# Run standard tests (regular CI, local development)
# - 50 proptest cases (or PROPTEST_CASES env var)
# - ~30 seconds
test:
    cargo nextest run --profile ci

# Run full tests (nightly, release validation)
# - 500 proptest cases
# - Includes ignored tests (load, scale, stress)
# - ~5 minutes
test-full:
    PROPTEST_CASES=500 cargo nextest run --profile full --features test-full --run-ignored all

# =============================================================================
# Development Shortcuts
# =============================================================================

# Run tests for a specific package
test-pkg pkg:
    cargo nextest run --profile ci -p {{pkg}}

# Run tests matching a pattern
test-filter filter:
    cargo nextest run --profile ci -E 'test({{filter}})'

# Run doc tests only
test-doc:
    cargo test --workspace --doc

# =============================================================================
# Build & Lint
# =============================================================================

# Build all workspace crates
build:
    cargo build --workspace

# Run clippy linter
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format code with nightly rustfmt
fmt:
    cargo +nightly fmt --all

# Check formatting without modifying
fmt-check:
    cargo +nightly fmt --all -- --check

# =============================================================================
# CI Simulation
# =============================================================================

# Simulate PR CI checks locally
ci-pr: fmt-check lint test-fast

# Simulate main branch CI checks locally
ci-main: fmt-check lint test

# Simulate full nightly CI checks locally
ci-nightly: fmt-check lint test-full

# =============================================================================
# Utilities
# =============================================================================

# Clean build artifacts
clean:
    cargo clean

# Update dependencies
update:
    cargo update

# Generate and open documentation
doc:
    cargo doc --workspace --no-deps --open
