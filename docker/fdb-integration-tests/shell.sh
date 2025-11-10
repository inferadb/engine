#!/bin/bash
# Get a shell in the test runner container for debugging

set -e

cd "$(dirname "$0")"

# Check if containers are running
if ! docker-compose ps | grep -q "test-runner.*Up"; then
    echo "Starting test environment..."
    docker-compose up -d
    echo "Waiting for services to be ready..."
    sleep 5
fi

echo "Opening shell in test runner container..."
echo "FDB cluster file: \$FDB_CLUSTER_FILE"
echo "Commands you can run:"
echo "  - cargo test -p infera-store --features fdb,fdb-integration-tests"
echo "  - fdbcli --exec status"
echo "  - /workspace/docker/fdb-integration-tests/run-tests.sh"
echo ""

docker-compose exec test-runner bash
