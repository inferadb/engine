#!/bin/bash
set -e

echo "=================================================="
echo "Azure Key Vault Integration Tests"
echo "=================================================="
echo ""

echo "ℹ️  Note: Azure doesn't provide an official Key Vault emulator."
echo "   Tests marked with #[ignore] require real Azure credentials."
echo "   Running unit tests only..."
echo ""

# Run the tests
echo "🧪 Running Azure Key Vault unit tests..."
echo ""

# Run only non-ignored tests (unit tests that don't require real Azure)
cargo test \
    --package infera-config \
    --features azure-secrets \
    --lib \
    azure \
    -- \
    --test-threads=1 \
    --nocapture \
    --skip test_azure_secrets_provider

TEST_EXIT_CODE=$?

echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ Azure Key Vault unit tests passed!"
    echo ""
    echo "ℹ️  To run integration tests with real Azure:"
    echo "   1. Set up Azure CLI authentication: az login"
    echo "   2. Set AZURE_VAULT_URL environment variable"
    echo "   3. Run: cargo test --package infera-config --features azure-secrets test_azure_secrets_provider -- --ignored"
else
    echo "❌ Azure Key Vault tests failed with exit code: $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
