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
FROM rust:1-slim AS builder
WORKDIR /app

# Use nightly Rust (required for some dependencies)
RUN rustup default nightly

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the application in release mode
RUN cargo build --release --bin inferadb-server

# Strip debug symbols to reduce binary size
RUN strip /app/target/release/inferadb-server

# ============================================================================
# Stage 2: Runtime - Minimal distroless image
# ============================================================================
FROM gcr.io/distroless/cc-debian12:latest

# Metadata labels
LABEL org.opencontainers.image.title="InferaDB"
LABEL org.opencontainers.image.description="High-performance authorization policy decision engine"
LABEL org.opencontainers.image.vendor="InferaDB"
LABEL org.opencontainers.image.licenses="BSL-1.1"
LABEL org.opencontainers.image.source="https://github.com/inferadb/inferadb"
LABEL org.opencontainers.image.documentation="https://docs.inferadb.com"

# Create non-root user (distroless uses uid/gid 65532:65532 for 'nonroot')
USER nonroot:nonroot

WORKDIR /app

# Copy the binary from builder
COPY --from=builder --chown=nonroot:nonroot /app/target/release/inferadb-server /app/inferadb-server

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
ENTRYPOINT ["/app/inferadb-server"]
CMD ["--config", "/etc/inferadb/config.yaml"]

# ============================================================================
# Build Instructions:
#
# Build the image:
#   docker build -t inferadb:latest .
#
# Build with specific tag:
#   docker build -t inferadb:v1.0.0 .
#
# Build with BuildKit (recommended for better caching):
#   DOCKER_BUILDKIT=1 docker build -t inferadb:latest .
#
# Run the container:
#   docker run -p 8080:8080 \
#     -v $(pwd)/config.yaml:/etc/inferadb/config.yaml \
#     inferadb:latest
#
# Security Scanning:
#   docker scan inferadb:latest
#   trivy image inferadb:latest
#   grype inferadb:latest
# ============================================================================
