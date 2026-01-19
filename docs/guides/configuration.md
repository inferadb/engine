# InferaDB Engine Configuration Guide

Complete guide for configuring the InferaDB Engine using configuration files and environment variables.

## Table of Contents

- [Overview](#overview)
- [Unified Configuration Format](#unified-configuration-format)
- [Configuration Methods](#configuration-methods)
- [Listen Configuration](#listen-configuration)
- [Storage Configuration](#storage-configuration)
- [Cache Configuration](#cache-configuration)
- [Logging Configuration](#logging-configuration)
- [Token Configuration](#token-configuration)
- [Identity Configuration](#identity-configuration)
- [Discovery Configuration](#discovery-configuration)
- [Mesh Configuration](#mesh-configuration)
- [Configuration Profiles](#configuration-profiles)
- [Secrets Management](#secrets-management)
- [Validation](#validation)
- [Best Practices](#best-practices)

## Overview

InferaDB supports configuration through multiple sources with the following precedence (highest to lowest):

1. **Environment variables** (highest priority)
2. **Configuration file**
3. **Default values** (lowest priority)

Configuration files use **YAML or JSON** format, and environment variables use the `INFERADB__` prefix with double underscores (`__`) as separators.

## Unified Configuration Format

InferaDB supports a **unified configuration format** that allows both Engine and Control services to share the same configuration file. Each service reads only its own section and ignores the other.

### Unified Config File Structure

```yaml
# config.yaml - shared by both services
engine:
  threads: 4
  logging: "info"
  listen:
    http: "127.0.0.1:8080"
    grpc: "127.0.0.1:8081"
    mesh: "0.0.0.0:8082"
  storage: "memory"
  # ... other engine config

control:
  threads: 4
  logging: "info"
  listen:
    http: "127.0.0.1:9090"
    grpc: "127.0.0.1:9091"
    mesh: "0.0.0.0:9092"
  storage: "memory"
  # ... other control config (ignored by engine)
```

### Using Unified Config

Both services can point to the same file:

```bash
# Start engine
inferadb-engine --config /etc/inferadb/config.yaml

# Start control
inferadb-control --config /etc/inferadb/config.yaml
```

### Environment Variables

With the unified format, environment variables use the `INFERADB__ENGINE__` prefix:

```bash
# Engine configuration
export INFERADB__ENGINE__THREADS=4
export INFERADB__ENGINE__LOGGING="info"
export INFERADB__ENGINE__LISTEN__HTTP="0.0.0.0:8080"
export INFERADB__ENGINE__STORAGE="ledger"

# Control configuration (uses INFERADB__CONTROL__ prefix)
export INFERADB__CONTROL__THREADS=4
export INFERADB__CONTROL__LISTEN__HTTP="0.0.0.0:9090"
```

## Configuration Methods

### Method 1: Configuration File

Create a `config.yaml` file using the unified format:

**YAML format** (recommended):

```yaml
engine:
  threads: 4
  logging: "info"

  listen:
    http: "0.0.0.0:8080"
    grpc: "0.0.0.0:8081"
    mesh: "0.0.0.0:8082"

  storage: "memory"
  ledger:
    endpoint: null

  cache:
    enabled: true
    capacity: 10000
    ttl: 300

  token:
    cache_ttl: 300
    clock_skew: 60
    max_age: 86400

  # Identity: pem is auto-generated if not set
  pem: null

  discovery:
    mode:
      type: none
    cache_ttl: 300

  mesh:
    url: "http://localhost:9092"
    timeout: 5000
    cache_ttl: 300
```

**Load configuration file**:

```bash
inferadb-engine --config config.yaml
```

### Method 2: Environment Variables

All configuration options can be set via environment variables using the `INFERADB__ENGINE__` prefix:

```bash
# Runtime configuration
export INFERADB__ENGINE__THREADS=4
export INFERADB__ENGINE__LOGGING="info"

# Listen addresses
export INFERADB__ENGINE__LISTEN__HTTP="0.0.0.0:8080"
export INFERADB__ENGINE__LISTEN__GRPC="0.0.0.0:8081"
export INFERADB__ENGINE__LISTEN__MESH="0.0.0.0:8082"

# Storage configuration
export INFERADB__ENGINE__STORAGE="ledger"
export INFERADB__ENGINE__LEDGER__ENDPOINT="http://ledger:50051"

# Cache configuration
export INFERADB__ENGINE__CACHE__ENABLED=true
export INFERADB__ENGINE__CACHE__CAPACITY=10000
export INFERADB__ENGINE__CACHE__TTL=300

# Token configuration
export INFERADB__ENGINE__TOKEN__CACHE_TTL=300

# Identity configuration
export INFERADB__ENGINE__PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Method 3: Combined (File + Environment)

Environment variables override file configuration:

```bash
# config.yaml sets engine.listen.http to "0.0.0.0:8080"
# Environment variable overrides to port 3000
export INFERADB__ENGINE__LISTEN__HTTP="0.0.0.0:3000"
inferadb-engine --config config.yaml
# HTTP server starts on port 3000
```

## Listen Configuration

Controls HTTP/gRPC server listen addresses. The Engine exposes three interfaces:

- **HTTP** (default `0.0.0.0:8080`): Client-facing REST API
- **gRPC** (default `0.0.0.0:8081`): Client-facing gRPC API
- **Mesh** (default `0.0.0.0:8082`): Service mesh / inter-service communication (JWKS, metrics, cache invalidation)

### Options

| Option | Type   | Default          | Description                                     |
| ------ | ------ | ---------------- | ----------------------------------------------- |
| `http` | string | `"0.0.0.0:8080"` | Client-facing HTTP/REST API address (host:port) |
| `grpc` | string | `"0.0.0.0:8081"` | Client-facing gRPC API address (host:port)      |
| `mesh` | string | `"0.0.0.0:8082"` | Service mesh address (JWKS, metrics, webhooks)  |

### Top-Level Options

| Option    | Type    | Default   | Description                                 |
| --------- | ------- | --------- | ------------------------------------------- |
| `threads` | integer | CPU count | Number of Tokio worker threads              |
| `logging` | string  | `"info"`  | Log level (trace, debug, info, warn, error) |

### Examples

**Development**:

```yaml
engine:
  threads: 2
  logging: "debug"
  listen:
    http: "0.0.0.0:8080"
    grpc: "0.0.0.0:8081"
    mesh: "0.0.0.0:8082"
```

**Production**:

```yaml
engine:
  threads: 8
  logging: "info"
  listen:
    http: "0.0.0.0:8080"
    grpc: "0.0.0.0:8081"
    mesh: "0.0.0.0:8082"
```

### Environment Variables

```bash
export INFERADB__ENGINE__THREADS=8
export INFERADB__ENGINE__LISTEN__HTTP="0.0.0.0:8080"
export INFERADB__ENGINE__LISTEN__GRPC="0.0.0.0:8081"
export INFERADB__ENGINE__LISTEN__MESH="0.0.0.0:8082"
```

### Recommendations

- **Development**: `threads: 2-4`
- **Production**: `threads: 1-2x CPU cores`
- **High-load**: `threads: 2-4x CPU cores`

## Storage Configuration

Controls the tuple storage backend.

### Options

| Option    | Type   | Default    | Description                                     |
| --------- | ------ | ---------- | ----------------------------------------------- |
| `storage` | string | `"memory"` | Storage backend: `"memory"` or `"ledger"` |

### Ledger Options

| Option            | Type              | Default | Description            |
| ----------------- | ----------------- | ------- | ---------------------- |
| `ledger.endpoint` | string (optional) | `null`  | Ledger gRPC endpoint   |

### Backend Options

#### Memory Backend (Development)

- **Use case**: Local development, testing
- **Persistence**: None (data lost on restart)
- **Performance**: Fastest
- **Configuration**: No cluster file needed

```yaml
engine:
  storage: "memory"
```

#### Ledger Backend (Production)

- **Use case**: Production deployments
- **Persistence**: ACID transactions, Raft-based replication
- **Performance**: High throughput, low latency
- **Configuration**: Requires Ledger gRPC endpoint

```yaml
engine:
  storage: "ledger"
  ledger:
    endpoint: "http://ledger:50051"
```

### Environment Variables

```bash
export INFERADB__ENGINE__STORAGE="ledger"
export INFERADB__ENGINE__LEDGER__ENDPOINT="http://ledger:50051"
```

### Recommendations

- **Development/Testing**: Use `memory` backend
- **Staging/Production**: Use `ledger` backend

## Cache Configuration

Controls the in-memory check result cache.

### Options

| Option     | Type    | Default | Description                            |
| ---------- | ------- | ------- | -------------------------------------- |
| `enabled`  | boolean | `true`  | Enable result caching                  |
| `capacity` | integer | `10000` | Maximum number of cached entries       |
| `ttl`      | integer | `300`   | Cache entry TTL in seconds (5 minutes) |

### Examples

**Small deployment**:

```yaml
engine:
  cache:
    enabled: true
    capacity: 10000
    ttl: 300
```

**Large deployment**:

```yaml
engine:
  cache:
    enabled: true
    capacity: 1000000
    ttl: 600
```

**Testing** (disable for predictability):

```yaml
engine:
  cache:
    enabled: false
```

### Environment Variables

```bash
export INFERADB__ENGINE__CACHE__ENABLED=true
export INFERADB__ENGINE__CACHE__CAPACITY=100000
export INFERADB__ENGINE__CACHE__TTL=600
```

### Memory Usage

Approximate memory usage per entry: 200-500 bytes

- 10,000 entries: 2-5 MB
- 100,000 entries: 20-50 MB
- 1,000,000 entries: 200-500 MB

### Recommendations

- **Development**: `capacity: 1,000-10,000`
- **Production**: `capacity: 100,000-1,000,000`
- **Low-latency workloads**: `ttl: 60-300`
- **Standard workloads**: `ttl: 300-600`
- **Static data**: `ttl: 3600+`

## Logging Configuration

Controls logging. Metrics and tracing are always enabled.

### Options

| Option    | Type   | Default  | Description                                                    |
| --------- | ------ | -------- | -------------------------------------------------------------- |
| `logging` | string | `"info"` | Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` |

> **Note**: Prometheus metrics (at `/metrics`) and OpenTelemetry distributed tracing are always enabled and cannot be disabled.

### Examples

**Development**:

```yaml
engine:
  logging: "debug"
```

**Production**:

```yaml
engine:
  logging: "info"
```

### Environment Variables

```bash
export INFERADB__ENGINE__LOGGING="info"
```

### Additional Configuration

**Granular logging** (via `RUST_LOG`):

```bash
# Set log level per module
export RUST_LOG="infera=debug,inferadb_engine_api=info,inferadb_engine_store=warn"
```

**OpenTelemetry tracing**:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"
export OTEL_SERVICE_NAME="inferadb"
```

### Recommendations

- **Development**: `logging: "debug"`
- **Production**: `logging: "info"`
- **Troubleshooting**: `logging: "debug"` temporarily
- **Low disk space**: `logging: "warn"` or `"error"`

## Token Configuration

Controls JWT token validation, including JWKS caching, timestamp tolerance, and token age limits.

### Options

| Option       | Type               | Default | Description                                |
| ------------ | ------------------ | ------- | ------------------------------------------ |
| `cache_ttl`  | integer            | `300`   | JWKS cache TTL in seconds (5 minutes)      |
| `clock_skew` | integer (optional) | `60`    | Clock skew tolerance in seconds (1 minute) |
| `max_age`    | integer (optional) | `86400` | Maximum token age in seconds (24 hours)    |

> **Note**: JWT algorithms are hardcoded to EdDSA and RS256 for security and cannot be configured.
>
> **Note**: The JWT audience is hardcoded to `https://api.inferadb.com` per RFC 8725 best practices.
> The audience identifies the InferaDB Engine API as the intended recipient, not a specific endpoint.
> This value must match the audience set by Control when generating tokens.

### Examples

**Development** (default settings):

```yaml
engine:
  token:
    cache_ttl: 300
```

**Production** (stricter validation):

```yaml
engine:
  token:
    cache_ttl: 300
    clock_skew: 30
    max_age: 3600
```

### Environment Variables

```bash
export INFERADB__ENGINE__TOKEN__CACHE_TTL=300
export INFERADB__ENGINE__TOKEN__CLOCK_SKEW=60
export INFERADB__ENGINE__TOKEN__MAX_AGE=86400
```

### Validation Warnings

- `clock_skew > 300` (5 minutes) generates a warning, as high tolerance may allow expired tokens
- `cache_ttl = 0` generates a warning, as this causes frequent JWKS fetches
- `cache_ttl > 3600` (1 hour) generates a warning for security reasons

## Identity Configuration

Controls Engine identity for service-to-service authentication with Control.

### Options

| Option | Type              | Default | Description                                                   |
| ------ | ----------------- | ------- | ------------------------------------------------------------- |
| `pem`  | string (optional) | `null`  | Ed25519 private key in PEM format (auto-generated if not set) |

### Example

```yaml
engine:
  pem: "${ENGINE_PRIVATE_KEY}"
```

Or with no configuration (key auto-generated at startup):

```yaml
engine:
  pem: null
```

### Environment Variables

```bash
export INFERADB__ENGINE__PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Recommendations

- In production, always provide `pem` rather than relying on auto-generation
- Use Kubernetes secrets or a secret manager for the private key
- The `kid` is deterministically derived from the public key (RFC 7638), so it remains consistent when using the same private key

## Discovery Configuration

Controls service discovery for multi-node deployments.

### Options

| Option                  | Type    | Default | Description                                  |
| ----------------------- | ------- | ------- | -------------------------------------------- |
| `mode`                  | object  | `none`  | Discovery mode configuration                 |
| `cache_ttl`             | integer | `300`   | Cache TTL for discovered endpoints (seconds) |
| `health_check_interval` | integer | `30`    | Health check interval (seconds)              |

### Discovery Modes

#### None (Default)

Direct connection to a single service URL:

```yaml
engine:
  discovery:
    mode:
      type: none
```

#### Kubernetes

Discover pod IPs via Kubernetes service:

```yaml
engine:
  discovery:
    mode:
      type: kubernetes
    cache_ttl: 30
    health_check_interval: 10
```

#### Tailscale

Multi-region discovery via Tailscale mesh:

```yaml
engine:
  discovery:
    mode:
      type: tailscale
      local_cluster: "us-west-1"
      remote_clusters:
        - name: "eu-west-1"
          tailscale_domain: "eu-west-1.ts.net"
          service_name: "inferadb-engine"
          port: 8082
        - name: "ap-southeast-1"
          tailscale_domain: "ap-southeast-1.ts.net"
          service_name: "inferadb-engine"
          port: 8082
    cache_ttl: 60
```

### Environment Variables

```bash
export INFERADB__ENGINE__DISCOVERY__CACHE_TTL=30
export INFERADB__ENGINE__DISCOVERY__HEALTH_CHECK_INTERVAL=10
```

## Mesh Configuration

Controls connection to InferaDB Control for JWKS fetching, org/vault validation, and certificate verification.

### Options

| Option           | Type    | Default                   | Description                                 |
| ---------------- | ------- | ------------------------- | ------------------------------------------- |
| `url`            | string  | `"http://localhost:9092"` | Control service base URL                    |
| `timeout`        | integer | `5000`                    | Timeout for mesh API calls (milliseconds)   |
| `cache_ttl`      | integer | `300`                     | Cache TTL for org/vault lookups (seconds)   |
| `cert_cache_ttl` | integer | `900`                     | Cache TTL for client certificates (seconds) |

### Examples

**Development**:

```yaml
engine:
  mesh:
    url: "http://localhost:9092"
    timeout: 5000
    cache_ttl: 300
```

**Kubernetes**:

```yaml
engine:
  mesh:
    url: "http://inferadb-control.inferadb:9092"
    timeout: 5000
    cache_ttl: 300
    cert_cache_ttl: 900
```

### Environment Variables

```bash
export INFERADB__ENGINE__MESH__URL="http://inferadb-control.inferadb:9092"
export INFERADB__ENGINE__MESH__TIMEOUT=5000
export INFERADB__ENGINE__MESH__CACHE_TTL=300
export INFERADB__ENGINE__MESH__CERT_CACHE_TTL=900
```

### Validation

- `url` must start with `http://` or `https://`
- `url` must not end with a trailing slash

## Configuration Profiles

### Development Profile

Optimized for local development:

```yaml
engine:
  threads: 2
  logging: "debug"

  listen:
    http: "0.0.0.0:8080"
    grpc: "0.0.0.0:8081"
    mesh: "0.0.0.0:8082"

  storage: "memory"

  cache:
    enabled: true
    capacity: 1000
    ttl: 60

  token:
    cache_ttl: 300

  pem: null

  discovery:
    mode:
      type: none

  mesh:
    url: "http://localhost:9092"
```

### Production Profile

Optimized for production deployment:

```yaml
engine:
  threads: 8
  logging: "info"

  listen:
    http: "0.0.0.0:8080"
    grpc: "0.0.0.0:8081"
    mesh: "0.0.0.0:8082"

  storage: "ledger"
  ledger:
    endpoint: "http://ledger:50051"

  cache:
    enabled: true
    capacity: 100000
    ttl: 300

  token:
    cache_ttl: 300
    clock_skew: 30
    max_age: 3600

  pem: "${ENGINE_PRIVATE_KEY}"

  discovery:
    mode:
      type: kubernetes
    cache_ttl: 30
    health_check_interval: 10

  mesh:
    url: "http://inferadb-control.inferadb:9092"
    timeout: 5000
    cache_ttl: 300
```

### Testing Profile

Optimized for predictable testing:

```yaml
engine:
  threads: 1
  logging: "warn"

  listen:
    http: "0.0.0.0:8080"
    grpc: "0.0.0.0:8081"
    mesh: "0.0.0.0:8082"

  storage: "memory"

  cache:
    enabled: false

  token:
    cache_ttl: 300

  pem: null

  discovery:
    mode:
      type: none

  mesh:
    url: "http://localhost:9092"
```

## Secrets Management

**Never commit secrets to configuration files.**

### Environment Variables (Recommended)

Use environment variables for sensitive values:

```bash
export INFERADB__ENGINE__PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: inferadb-engine-secrets
type: Opaque
stringData:
  private-key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

```yaml
# In deployment
env:
  - name: INFERADB__ENGINE__PEM
    valueFrom:
      secretKeyRef:
        name: inferadb-engine-secrets
        key: private-key
```

### External Secret Managers

**AWS Secrets Manager**:

```bash
export INFERADB__ENGINE__PEM=$(aws secretsmanager get-secret-value \
  --secret-id inferadb/engine/private-key \
  --query SecretString --output text)
```

**HashiCorp Vault**:

```bash
export INFERADB__ENGINE__PEM=$(vault kv get \
  -field=private_key secret/inferadb/engine)
```

## Validation

InferaDB validates configuration at startup. Invalid configurations fail fast with clear error messages.

### Validation Rules

**Listen**:

- `listen.http`, `listen.grpc`, `listen.mesh` must be valid socket addresses (e.g., `"0.0.0.0:8080"`)

**Top-Level**:

- `threads` must be > 0
- `logging` must be valid: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`

**Storage**:

- `storage` must be `"memory"` or `"ledger"`
- `ledger.endpoint` required when `storage = "ledger"`

**Cache**:

- `capacity` must be > 0 when enabled
- `ttl` must be > 0

**Token**:

- Algorithms are hardcoded to EdDSA and RS256 (not configurable)
- Audience is hardcoded to `https://api.inferadb.com` (not configurable)
- `clock_skew > 300` generates warning

**Identity**:

- `pem` is optional (auto-generated if not set)

**Mesh**:

- `mesh.url` must start with `http://` or `https://`
- `mesh.url` must not end with trailing slash

### Example Validation Errors

```text
Error: Invalid storage: 'postgres'. Must be 'memory' or 'ledger'
```

```text
Error: ledger.endpoint is required when using Ledger backend
```

```text
Error: listen.http '0.0.0.0' is not a valid socket address
```

```text
Error: mesh.url must start with http:// or https://
```

```text
Error: Invalid logging level: 'verbose'. Must be one of: trace, debug, info, warn, error
```

## Best Practices

### Security

1. **Asymmetric algorithms only** - Algorithms are hardcoded to EdDSA and RS256 for security

2. **Audience validation** - The JWT audience is hardcoded to `https://api.inferadb.com` per RFC 8725 best practices. This ensures tokens are issued for the InferaDB Engine API (not a specific endpoint).

3. **Never commit secrets**
   - Use environment variables
   - Use secret managers
   - Use `.gitignore` for config files with secrets

### Performance

1. **Tune worker threads**
   - CPU-bound: 2x CPU cores
   - I/O-bound: 4-8x CPU cores
   - Benchmark and adjust

2. **Optimize cache settings**
   - Increase `capacity` for large datasets
   - Adjust `ttl` based on update frequency
   - Monitor cache hit rate (target >80%)

3. **Use Ledger in production**
   - Memory backend doesn't persist
   - Ledger provides ACID + Raft replication

### Observability

1. **Enable metrics and tracing**

   Metrics and tracing are always enabled.

2. **Choose appropriate log level**
   - Production: `"info"`
   - Development: `"debug"`
   - Troubleshooting: `"debug"` temporarily

3. **Monitor key metrics**
   - Request latency (p50, p90, p99)
   - Error rate
   - Cache hit rate
   - Active connections

### Operations

1. **Use configuration files for defaults**
   - Non-sensitive configuration
   - Version control tracked

2. **Use environment variables for overrides**
   - Secrets
   - Environment-specific values
   - Dynamic configuration

3. **Validate before deploying**

   ```bash
   inferadb-engine --config config.yaml --validate
   ```

## Deployment Examples

### Docker Compose

```yaml
version: "3.8"
services:
  inferadb-engine:
    image: inferadb/inferadb-engine:latest
    ports:
      - "8080:8080"
      - "8081:8081"
      - "8082:8082"
    environment:
      INFERADB__ENGINE__LISTEN__HTTP: "0.0.0.0:8080"
      INFERADB__ENGINE__LISTEN__GRPC: "0.0.0.0:8081"
      INFERADB__ENGINE__LISTEN__MESH: "0.0.0.0:8082"
      INFERADB__ENGINE__STORAGE: "ledger"
      INFERADB__ENGINE__LEDGER__ENDPOINT: "http://ledger:50051"
      INFERADB__ENGINE__MESH__URL: "http://control:9092"
```

### Kubernetes

See [Deployment Guide](deployment.md) for complete Kubernetes manifests.

## Troubleshooting

### Engine Won't Start

**Check configuration**:

```bash
inferadb-engine --config config.yaml --validate
inferadb-engine --config config.yaml 2>&1 | grep ERROR
```

### Port Already in Use

```bash
# Find process
lsof -i :8080

# Change port
export INFERADB__ENGINE__LISTEN__HTTP="0.0.0.0:8090"
```

### Out of Memory

Reduce cache size:

```yaml
engine:
  cache:
    capacity: 10000
```

### Slow Performance

1. Check cache enabled: `cache.enabled = true`
2. Check cache hit rate: `/metrics` endpoint
3. Increase worker threads for high load

## See Also

- [Authentication Guide](../security/authentication.md) - Detailed authentication setup
- [Deployment Guide](deployment.md) - Production deployment
- [Control Configuration](../../../../control/docs/guides/configuration.md) - Control configuration
