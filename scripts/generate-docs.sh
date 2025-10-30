#!/usr/bin/env bash
# Generate comprehensive Rustdoc documentation for all crates
#
# This script uses mise if available to ensure the correct Rust version,
# but falls back to system cargo if mise is not installed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "🔨 Generating Rustdoc documentation for InferaDB..."
echo ""

# Use mise if available, otherwise fall back to cargo
if command -v mise &> /dev/null; then
    CARGO_CMD="mise exec -- cargo"
else
    CARGO_CMD="cargo"
fi

# Generate documentation with all features enabled
echo "📚 Building documentation with private items..."
RUSTDOCFLAGS="--html-in-header ${PROJECT_ROOT}/docs/rustdoc-header.html" \
  ${CARGO_CMD} doc \
    --workspace \
    --no-deps \
    --document-private-items \
    --all-features \
    --lib

echo ""
echo "✅ Documentation generated successfully!"
echo ""
echo "📖 Open documentation at: file://${PROJECT_ROOT}/target/doc/inferadb/index.html"
echo ""
echo "📦 Documented crates:"
echo "  - infera-api       → API layer (REST + gRPC)"
echo "  - infera-auth      → Authentication & authorization"
echo "  - infera-cache     → Result caching"
echo "  - infera-config    → Configuration management"
echo "  - infera-core      → Policy evaluation engine"
echo "  - infera-observe   → Observability (metrics, tracing, logging)"
echo "  - infera-repl      → Replication & consistency"
echo "  - infera-store     → Storage abstraction"
echo "  - infera-wasm      → WASM policy modules"
echo ""
echo "💡 To open in browser:"
echo "   open target/doc/inferadb/index.html    # macOS"
echo "   xdg-open target/doc/inferadb/index.html # Linux"
echo ""
