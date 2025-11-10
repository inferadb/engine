#!/bin/bash
# FoundationDB Integration Test Runner
# This script waits for FDB to be ready and runs the integration tests

set -e

echo "=== InferaDB FoundationDB Integration Tests ==="
echo "Starting at $(date)"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if FDB is ready
check_fdb_ready() {
    if [ ! -f "$FDB_CLUSTER_FILE" ]; then
        return 1
    fi

    # Try to connect to FDB and check status
    local status_output
    status_output=$(fdbcli --exec "status" 2>&1)
    local status_exit=$?

    if [ $status_exit -ne 0 ]; then
        return 1
    fi

    # Check if data distribution is initializing
    if echo "$status_output" | grep -q "(Re)initializing"; then
        return 1
    fi

    # Check if we have "Replication health" that's not unknown
    if echo "$status_output" | grep -q "Replication health.*unknown"; then
        return 1
    fi

    return 0
}

# Wait for FDB cluster file
echo "Waiting for FDB cluster file at $FDB_CLUSTER_FILE..."
MAX_WAIT=60
ELAPSED=0

while [ ! -f "$FDB_CLUSTER_FILE" ]; do
    if [ $ELAPSED -ge $MAX_WAIT ]; then
        echo -e "${RED}✗ Timeout waiting for FDB cluster file${NC}"
        exit 1
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -n "."
done

echo -e "\n${GREEN}✓ Cluster file found${NC}"
echo "Cluster file contents:"
cat "$FDB_CLUSTER_FILE"
echo ""

# Initialize FDB cluster if needed
echo "Initializing FDB cluster..."
fdbcli --exec "configure new single memory" 2>/dev/null || {
    echo "Cluster already configured or configuring..."
}

# Wait for FDB to be ready
echo "Waiting for FDB to be ready..."
MAX_WAIT=120
ELAPSED=0

while ! check_fdb_ready; do
    if [ $ELAPSED -ge $MAX_WAIT ]; then
        echo -e "${RED}✗ Timeout waiting for FDB to be ready${NC}"
        echo "FDB Status:"
        fdbcli --exec "status" || true
        exit 1
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    echo -n "."
done

echo -e "\n${GREEN}✓ FDB is ready${NC}"
echo ""

# Show FDB status
echo "=== FDB Cluster Status ==="
fdbcli --exec "status"
echo ""

# Run the integration tests
echo "=== Running Integration Tests ==="
echo ""

cd /workspace

# Run FDB-specific integration tests
echo -e "${YELLOW}Running FDB integration tests...${NC}"
cargo test -p infera-store \
    --features fdb,fdb-integration-tests \
    --lib foundationdb::tests \
    -- --nocapture --test-threads=1

TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}=== All tests passed! ===${NC}"
else
    echo ""
    echo -e "${RED}=== Tests failed with exit code $TEST_EXIT_CODE ===${NC}"
fi

# Optional: Run all storage tests for comprehensive validation
if [ "${RUN_ALL_TESTS:-false}" = "true" ]; then
    echo ""
    echo -e "${YELLOW}Running all storage layer tests...${NC}"
    cargo test -p infera-store -- --nocapture
fi

echo ""
echo "Finished at $(date)"

exit $TEST_EXIT_CODE
