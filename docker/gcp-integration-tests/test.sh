#!/bin/bash
set -e

echo "=================================================="
echo "InferaDB - GCP Secret Manager Integration Tests"
echo "=================================================="
echo ""

# Change to the docker/gcp-integration-tests directory
cd "$(dirname "$0")"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running"
    echo "Please start Docker and try again"
    exit 1
fi

echo "🏗️  Building test environment..."
docker-compose build --quiet

echo "🚀 Starting GCP emulator and test runner..."
docker-compose up --abort-on-container-exit --exit-code-from test-runner

TEST_EXIT_CODE=$?

echo ""
echo "🧹 Cleaning up..."
docker-compose down --volumes

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Tests failed with exit code: $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
