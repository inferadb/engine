# Dockerfile for GCP Secret Manager Integration Tests
FROM rust:1-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Use nightly Rust (required for some dependencies)
RUN rustup default nightly

WORKDIR /workspace

# The actual test execution will happen via the run-tests.sh script
CMD ["bash"]
