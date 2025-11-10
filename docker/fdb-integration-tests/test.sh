#!/bin/bash
# Convenience wrapper to run FDB integration tests
# Usage: ./docker/fdb-integration-tests/test.sh

set -e

cd "$(dirname "$0")"

echo "Starting FDB Integration Test Environment..."
echo ""

# Build and start services
docker-compose up -d --build

echo ""
echo "Waiting for services to be ready..."
sleep 5

# Run tests
echo ""
echo "Executing tests..."
docker-compose exec test-runner /workspace/docker/fdb-integration-tests/run-tests.sh

# Capture exit code
TEST_EXIT_CODE=$?

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✓ Tests completed successfully"
else
    echo "✗ Tests failed"
fi

# Optional: Keep services running for debugging
if [ "${KEEP_RUNNING:-false}" = "true" ]; then
    echo ""
    echo "Services kept running for debugging."
    echo "Access test runner: docker-compose exec test-runner bash"
    echo "Stop with: docker-compose down"
else
    echo ""
    echo "Cleaning up..."
    docker-compose down
fi

exit $TEST_EXIT_CODE
