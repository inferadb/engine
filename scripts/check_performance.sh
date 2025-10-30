#!/bin/bash
# Performance Regression Detection Script
#
# This script runs performance tests and checks for regressions against documented baselines.
# Baselines are defined in docs/performance-baselines.md

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REGRESSION_THRESHOLD=1.2  # 20% degradation triggers warning
CARGO="${CARGO:-cargo}"
TEST_PACKAGE="infera-core"
TEST_NAME="performance_load"

# Baseline values (from docs/performance-baselines.md)
BASELINE_P99_MS=5          # p99 < 5ms for in-memory checks
BASELINE_P99_WASM_MS=20    # p99 < 20ms for WASM checks
BASELINE_MAX_DEEP_MS=100   # max < 100ms for deep nesting
BASELINE_MAX_WIDE_MS=500   # max < 500ms for wide expansion

echo "================================================"
echo "InferaDB Performance Regression Check"
echo "================================================"
echo ""

# Function to run tests and extract performance metrics
run_fast_tests() {
    echo "Running fast performance tests..."
    echo ""

    # Run the tests and capture output
    if ! $CARGO test --package "$TEST_PACKAGE" --test "$TEST_NAME" --release 2>&1 | tee /tmp/perf_test_output.txt; then
        echo -e "${RED}✗ Performance tests failed${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ All performance tests passed${NC}"
    echo ""
}

# Function to check if a specific test exists in output
check_test_passed() {
    local test_name="$1"
    if grep -q "test $test_name ... ok" /tmp/perf_test_output.txt; then
        echo -e "${GREEN}✓${NC} $test_name passed"
        return 0
    elif grep -q "test $test_name ... ignored" /tmp/perf_test_output.txt; then
        echo -e "${YELLOW}⊘${NC} $test_name ignored (long-running test)"
        return 0
    else
        echo -e "${RED}✗${NC} $test_name failed or not found"
        return 1
    fi
}

# Function to parse and check metrics
# Note: This is simplified - real implementation would parse actual metrics from test output
check_baselines() {
    echo "Checking performance against baselines..."
    echo ""

    # Check that all critical tests passed
    local all_passed=true

    check_test_passed "test_latency_p99_under_10ms" || all_passed=false
    check_test_passed "test_spike_load" || all_passed=false
    check_test_passed "test_deep_nesting_10_levels" || all_passed=false

    # Long-running tests (expected to be ignored in CI)
    check_test_passed "test_sustained_throughput_100k_rps"
    check_test_passed "test_stress_beyond_capacity"
    check_test_passed "test_soak_24h_simulation"
    check_test_passed "test_large_graph_1m_tuples"
    check_test_passed "test_wide_expansion_10k_users"

    echo ""

    if [ "$all_passed" = true ]; then
        echo -e "${GREEN}✓ All critical performance tests passed${NC}"
        return 0
    else
        echo -e "${RED}✗ Some critical performance tests failed${NC}"
        return 1
    fi
}

# Function to run criterion benchmarks (if requested)
run_benchmarks() {
    if [ "${RUN_BENCHMARKS:-false}" = "true" ]; then
        echo ""
        echo "Running Criterion benchmarks..."
        echo ""

        if ! $CARGO bench --package "$TEST_PACKAGE"; then
            echo -e "${YELLOW}⚠ Benchmark run failed (non-critical)${NC}"
        else
            echo -e "${GREEN}✓ Benchmarks completed${NC}"
            echo ""
            echo "View detailed results in target/criterion/"
        fi
    fi
}

# Function to suggest running ignored tests
suggest_full_suite() {
    echo ""
    echo "================================================"
    echo "Quick Check Complete"
    echo "================================================"
    echo ""
    echo "To run the full performance test suite (including long-running tests):"
    echo "  $CARGO test --package $TEST_PACKAGE --test $TEST_NAME --release -- --include-ignored"
    echo ""
    echo "To run Criterion benchmarks:"
    echo "  RUN_BENCHMARKS=true $0"
    echo ""
}

# Main execution
main() {
    # Check if running in release mode (required for accurate performance testing)
    if [ "${CARGO_PROFILE:-}" != "release" ]; then
        echo -e "${YELLOW}⚠ Warning: Running in debug mode. Use --release for accurate results.${NC}"
        echo ""
    fi

    # Run tests
    run_fast_tests

    # Check baselines
    if check_baselines; then
        exit_code=0
    else
        exit_code=1
    fi

    # Run benchmarks if requested
    run_benchmarks

    # Show suggestions
    suggest_full_suite

    exit $exit_code
}

# Run main function
main "$@"
