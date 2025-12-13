# Multi-stage Dockerfile for InferaDB
#
# This Dockerfile builds a minimal, secure production image using:
# - Multi-stage build to minimize final image size
# - Distroless base image for security
# - Official Rust Docker images only
# - Security scanning ready

# ============================================================================
# Stage 1: Builder - Build the application
# ============================================================================
FROM rustlang/rust:nightly-bookworm-slim AS builder
WORKDIR /app

# Install build dependencies including FoundationDB client
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    wget \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Install FoundationDB client library (required for fdb feature)
# Detect architecture and download appropriate package
# Note: FDB uses 'aarch64' for ARM64 in their release URLs
RUN ARCH=$(dpkg --print-architecture) && \
    FDB_VERSION="7.3.69" && \
    if [ "$ARCH" = "amd64" ]; then \
        wget -q https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_amd64.deb && \
        dpkg -i foundationdb-clients_${FDB_VERSION}-1_amd64.deb && \
        rm foundationdb-clients_${FDB_VERSION}-1_amd64.deb; \
    elif [ "$ARCH" = "arm64" ]; then \
        wget -q https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_aarch64.deb && \
        dpkg -i foundationdb-clients_${FDB_VERSION}-1_aarch64.deb && \
        rm foundationdb-clients_${FDB_VERSION}-1_aarch64.deb; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi

# Copy source code
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the application in release mode with FoundationDB support
RUN cargo build --release --bin inferadb-engine --features fdb

# Strip debug symbols to reduce binary size
RUN strip /app/target/release/inferadb-engine

# ============================================================================
# Stage 2: Runtime - Minimal Debian slim image
# ============================================================================
FROM debian:bookworm-slim

# Metadata labels
LABEL org.opencontainers.image.title="InferaDB"
LABEL org.opencontainers.image.description="High-performance authorization policy decision engine"
LABEL org.opencontainers.image.vendor="InferaDB"
LABEL org.opencontainers.image.licenses="BSL-1.1"
LABEL org.opencontainers.image.source="https://github.com/inferadb/inferadb"
LABEL org.opencontainers.image.documentation="https://docs.inferadb.com"

# Install runtime dependencies including FoundationDB client
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install FoundationDB client library (required at runtime for FDB backend)
# Detect architecture and download appropriate package
# Note: FDB uses 'aarch64' for ARM64 in their release URLs
RUN ARCH=$(dpkg --print-architecture) && \
    FDB_VERSION="7.3.69" && \
    if [ "$ARCH" = "amd64" ]; then \
        wget -q https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_amd64.deb && \
        dpkg -i foundationdb-clients_${FDB_VERSION}-1_amd64.deb && \
        rm foundationdb-clients_${FDB_VERSION}-1_amd64.deb; \
    elif [ "$ARCH" = "arm64" ]; then \
        wget -q https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_aarch64.deb && \
        dpkg -i foundationdb-clients_${FDB_VERSION}-1_aarch64.deb && \
        rm foundationdb-clients_${FDB_VERSION}-1_aarch64.deb; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    apt-get purge -y wget && \
    apt-get autoremove -y

# Create non-root user
RUN useradd -r -u 65532 -s /sbin/nologin nonroot

USER nonroot:nonroot

WORKDIR /app

# Copy the binary from builder
COPY --from=builder --chown=nonroot:nonroot /app/target/release/inferadb-engine /app/inferadb-engine

# Expose gRPC port (default 8080)
EXPOSE 8080

# Expose metrics port (if different from main port)
# EXPOSE 9090

# Health check configuration
# Note: distroless doesn't include curl/wget, so we rely on Kubernetes health checks
HEALTHCHECK NONE

# Set environment variables for production
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Run the binary
ENTRYPOINT ["/app/inferadb-engine"]
CMD ["--config", "/etc/inferadb/config.yaml"]

# ============================================================================
# Build Instructions:
#
# Build the image:
#   docker build -t inferadb-engine:latest .
#
# Build with specific tag:
#   docker build -t inferadb-engine:v1.0.0 .
#
# Build with BuildKit (recommended for better caching):
#   DOCKER_BUILDKIT=1 docker build -t inferadb-engine:latest .
#
# Run the container:
#   docker run -p 8080:8080 \
#     -v $(pwd)/config.yaml:/etc/inferadb/config.yaml \
#     inferadb-engine:latest
#
# Security Scanning:
#   docker scan inferadb-engine:latest
#   trivy image inferadb-engine:latest
#   grype inferadb-engine:latest
# ============================================================================
