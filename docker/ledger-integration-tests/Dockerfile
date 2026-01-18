# Test runner for Engine + Ledger integration tests
#
# Uses the official Rust image with all dependencies needed to build and run
# Engine integration tests against a real Ledger cluster.

FROM rust:1.85-bookworm

# Install protobuf compiler and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    libprotobuf-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Default command runs the Ledger integration tests
CMD ["cargo", "test", "--package", "inferadb-engine-api", "--test", "ledger_integration", "--", "--test-threads=1"]
