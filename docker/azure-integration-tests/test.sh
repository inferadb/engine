#!/bin/bash
set -e

echo "=================================================="
echo "InferaDB - Azure Key Vault Integration Tests"
echo "=================================================="
echo ""

cd "$(dirname "$0")"

echo "🏗️  Building test environment..."
docker-compose build --quiet

echo "🚀 Starting test runner..."
docker-compose up --abort-on-container-exit --exit-code-from test-runner

EXIT_CODE=$?

echo ""
echo "🧹 Cleaning up..."
docker-compose down -v > /dev/null 2>&1

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "❌ Tests failed with exit code: $EXIT_CODE"
fi

exit $EXIT_CODE
