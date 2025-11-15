# Dockerfile for AWS Secrets Manager Integration Tests
FROM rust:1-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Use nightly Rust (required for some dependencies)
RUN rustup default nightly

# Install AWS CLI for test setup (detect architecture)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then \
        AWSCLI_ARCH="aarch64"; \
    else \
        AWSCLI_ARCH="x86_64"; \
    fi && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-${AWSCLI_ARCH}.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf aws awscliv2.zip

WORKDIR /workspace

# The actual test execution will happen via the run-tests.sh script
CMD ["bash"]
