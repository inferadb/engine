#!/bin/bash
set -e

echo "=================================================="
echo "AWS Secrets Manager Integration Tests"
echo "=================================================="
echo ""

# Wait for LocalStack to be fully ready
echo "⏳ Waiting for LocalStack to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -s http://localstack:4566/_localstack/health | grep -q '"secretsmanager": "available"'; then
        echo "✅ LocalStack is ready!"
        break
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        echo "❌ LocalStack failed to become ready after $MAX_RETRIES attempts"
        exit 1
    fi

    echo "   Attempt $RETRY_COUNT/$MAX_RETRIES - waiting..."
    sleep 2
done

echo ""
echo "🔧 Setting up test secrets in LocalStack..."

# Create test secrets using AWS CLI
aws --endpoint-url=http://localstack:4566 secretsmanager create-secret \
    --name test-secret-1 \
    --secret-string '{"username":"testuser","password":"testpass"}' \
    2>/dev/null || echo "   Secret test-secret-1 already exists"

aws --endpoint-url=http://localstack:4566 secretsmanager create-secret \
    --name test-secret-2 \
    --secret-string 'my-test-value' \
    2>/dev/null || echo "   Secret test-secret-2 already exists"

echo "✅ Test secrets created"
echo ""

# Run the tests
echo "🧪 Running AWS Secrets Manager integration tests..."
echo ""

cargo test \
    --package infera-config \
    --features aws-secrets \
    --lib \
    -- \
    --test-threads=1 \
    --nocapture

TEST_EXIT_CODE=$?

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ AWS Secrets Manager tests passed!"
else
    echo "❌ AWS Secrets Manager tests failed with exit code: $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
