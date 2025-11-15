#!/bin/bash
set -e

echo "=================================================="
echo "GCP Secret Manager Integration Tests"
echo "=================================================="
echo ""

echo "ℹ️  Note: GCP doesn't provide an official Secret Manager emulator."
echo "   Tests marked with #[ignore] require real GCP credentials."
echo "   Running unit tests only..."
echo ""

# Run the tests
echo "🧪 Running GCP Secret Manager unit tests..."
echo ""

# Run only non-ignored tests (unit tests that don't require real GCP)
cargo test \
    --package infera-config \
    --features gcp-secrets \
    --lib \
    gcp \
    -- \
    --test-threads=1 \
    --nocapture \
    --skip test_gcp_secrets_provider

TEST_EXIT_CODE=$?

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ GCP Secret Manager unit tests passed!"
    echo ""
    echo "ℹ️  To run integration tests with real GCP:"
    echo "   1. Set up Application Default Credentials: gcloud auth application-default login"
    echo "   2. Set GCP_PROJECT_ID environment variable"
    echo "   3. Run: cargo test --package infera-config --features gcp-secrets test_gcp_secrets_provider -- --ignored"
else
    echo "❌ GCP Secret Manager tests failed with exit code: $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
