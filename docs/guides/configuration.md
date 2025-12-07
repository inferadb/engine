# InferaDB Server Configuration Guide

Complete guide for configuring the InferaDB server using configuration files and environment variables.

## Table of Contents

- [Overview](#overview)
- [Configuration Methods](#configuration-methods)
- [Server Configuration](#server-configuration)
- [Storage Configuration](#storage-configuration)
- [Cache Configuration](#cache-configuration)
- [Observability Configuration](#observability-configuration)
- [Authentication Configuration](#authentication-configuration)
- [Identity Configuration](#identity-configuration)
- [Discovery Configuration](#discovery-configuration)
- [Management Service Configuration](#management-service-configuration)
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

## Configuration Methods

### Method 1: Configuration File

Create a `config.yaml` or `config.json` file:

**YAML format** (recommended):

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 8081
  internal_host: "0.0.0.0"
  internal_port: 8082
  worker_threads: 4

storage:
  backend: "memory"
  fdb_cluster_file: null

cache:
  enabled: true
  max_capacity: 10000
  ttl: 300

observability:
  log_level: "info"
  metrics_enabled: true
  tracing_enabled: true

auth:
  jwks_cache_ttl: 300

# Identity: server_id and kid are auto-generated
identity: {}

discovery:
  mode:
    type: none
  cache_ttl: 300

management_service:
  service_url: "http://localhost:9092"
  internal_port: 9092
```

**Load configuration file**:

```bash
inferadb-server --config config.yaml
```

### Method 2: Environment Variables

All configuration options can be set via environment variables using the `INFERADB__` prefix:

```bash
# Server configuration
export INFERADB__SERVER__HOST="0.0.0.0"
export INFERADB__SERVER__PORT=8080
export INFERADB__SERVER__GRPC_PORT=8081
export INFERADB__SERVER__INTERNAL_HOST="0.0.0.0"
export INFERADB__SERVER__INTERNAL_PORT=8082
export INFERADB__SERVER__WORKER_THREADS=4

# Storage configuration
export INFERADB__STORAGE__BACKEND="memory"
export INFERADB__STORAGE__FDB_CLUSTER_FILE="/etc/foundationdb/fdb.cluster"

# Cache configuration
export INFERADB__CACHE__ENABLED=true
export INFERADB__CACHE__MAX_CAPACITY=10000
export INFERADB__CACHE__TTL=300

# Observability configuration
export INFERADB__OBSERVABILITY__LOG_LEVEL="info"
export INFERADB__OBSERVABILITY__METRICS_ENABLED=true
export INFERADB__OBSERVABILITY__TRACING_ENABLED=true

# Identity configuration
export INFERADB__IDENTITY__PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Method 3: Combined (File + Environment)

Environment variables override file configuration:

```bash
# config.yaml sets port to 8080
# Environment variable overrides to 3000
export INFERADB__SERVER__PORT=3000
inferadb-server --config config.yaml
# Server starts on port 3000
```

## Server Configuration

Controls HTTP/gRPC server behavior. The server exposes three interfaces:

- **Public REST API** (port 8080): Client-facing HTTP API
- **Public gRPC API** (port 8081): Client-facing gRPC API
- **Internal REST API** (port 8082): Server-to-server communication

### Options

| Option           | Type    | Default     | Description                                 |
| ---------------- | ------- | ----------- | ------------------------------------------- |
| `host`           | string  | `"0.0.0.0"` | Public REST API bind address                |
| `port`           | integer | `8080`      | Public REST API port                        |
| `grpc_port`      | integer | `8081`      | Public gRPC API port                        |
| `internal_host`  | string  | `"0.0.0.0"` | Internal REST API bind address              |
| `internal_port`  | integer | `8082`      | Internal REST API port (cache invalidation) |
| `worker_threads` | integer | CPU count   | Number of Tokio worker threads              |

### Examples

**Development** (all interfaces):

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 8081
  internal_host: "0.0.0.0"
  internal_port: 8082
  worker_threads: 2
```

**Production** (all interfaces, more workers):

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 8081
  internal_host: "0.0.0.0"
  internal_port: 8082
  worker_threads: 8
```

### Environment Variables

```bash
export INFERADB__SERVER__HOST="0.0.0.0"
export INFERADB__SERVER__PORT=8080
export INFERADB__SERVER__GRPC_PORT=8081
export INFERADB__SERVER__INTERNAL_HOST="0.0.0.0"
export INFERADB__SERVER__INTERNAL_PORT=8082
export INFERADB__SERVER__WORKER_THREADS=8
```

### Recommendations

- **Development**: `worker_threads: 2-4`
- **Production**: `worker_threads: 1-2x CPU cores`
- **High-load**: `worker_threads: 2-4x CPU cores`

## Storage Configuration

Controls the tuple storage backend.

### Options

| Option             | Type              | Default    | Description                                     |
| ------------------ | ----------------- | ---------- | ----------------------------------------------- |
| `backend`          | string            | `"memory"` | Storage backend: `"memory"` or `"foundationdb"` |
| `fdb_cluster_file` | string (optional) | `null`     | Path to FoundationDB cluster file               |

### Backend Options

#### Memory Backend (Development)

- **Use case**: Local development, testing
- **Persistence**: None (data lost on restart)
- **Performance**: Fastest
- **Configuration**: No cluster file needed

```yaml
storage:
  backend: "memory"
```

#### FoundationDB Backend (Production)

- **Use case**: Production deployments
- **Persistence**: ACID transactions, replication
- **Performance**: High throughput, low latency
- **Configuration**: Requires FDB cluster file path

```yaml
storage:
  backend: "foundationdb"
  fdb_cluster_file: "/etc/foundationdb/fdb.cluster"
```

### Environment Variables

```bash
export INFERADB__STORAGE__BACKEND="foundationdb"
export INFERADB__STORAGE__FDB_CLUSTER_FILE="/etc/foundationdb/fdb.cluster"
```

### Recommendations

- **Development/Testing**: Use `memory` backend
- **Staging/Production**: Use `foundationdb` backend

## Cache Configuration

Controls the in-memory check result cache.

### Options

| Option         | Type    | Default | Description                      |
| -------------- | ------- | ------- | -------------------------------- |
| `enabled`      | boolean | `true`  | Enable result caching            |
| `max_capacity` | integer | `10000` | Maximum number of cached entries |
| `ttl`          | integer | `300`   | Cache entry TTL in seconds (5 minutes) |

### Examples

**Small deployment**:

```yaml
cache:
  enabled: true
  max_capacity: 10000
  ttl: 300
```

**Large deployment**:

```yaml
cache:
  enabled: true
  max_capacity: 1000000
  ttl: 600
```

**Testing** (disable for predictability):

```yaml
cache:
  enabled: false
```

### Environment Variables

```bash
export INFERADB__CACHE__ENABLED=true
export INFERADB__CACHE__MAX_CAPACITY=100000
export INFERADB__CACHE__TTL=600
```

### Memory Usage

Approximate memory usage per entry: 200-500 bytes

- 10,000 entries: 2-5 MB
- 100,000 entries: 20-50 MB
- 1,000,000 entries: 200-500 MB

### Recommendations

- **Development**: `max_capacity: 1,000-10,000`
- **Production**: `max_capacity: 100,000-1,000,000`
- **Low-latency workloads**: `ttl: 60-300`
- **Standard workloads**: `ttl: 300-600`
- **Static data**: `ttl: 3600+`

## Observability Configuration

Controls logging, metrics, and tracing.

### Options

| Option            | Type    | Default  | Description                                                    |
| ----------------- | ------- | -------- | -------------------------------------------------------------- |
| `log_level`       | string  | `"info"` | Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` |
| `metrics_enabled` | boolean | `true`   | Enable Prometheus metrics at `/metrics`                        |
| `tracing_enabled` | boolean | `true`   | Enable OpenTelemetry distributed tracing                       |

### Examples

**Development**:

```yaml
observability:
  log_level: "debug"
  metrics_enabled: true
  tracing_enabled: false
```

**Production**:

```yaml
observability:
  log_level: "info"
  metrics_enabled: true
  tracing_enabled: true
```

### Environment Variables

```bash
export INFERADB__OBSERVABILITY__LOG_LEVEL="info"
export INFERADB__OBSERVABILITY__METRICS_ENABLED=true
export INFERADB__OBSERVABILITY__TRACING_ENABLED=true
```

### Additional Configuration

**Granular logging** (via `RUST_LOG`):

```bash
# Set log level per module
export RUST_LOG="infera=debug,inferadb_api=info,inferadb_store=warn"
```

**OpenTelemetry tracing**:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"
export OTEL_SERVICE_NAME="inferadb"
```

### Recommendations

- **Development**: `log_level: "debug"`, `tracing_enabled: false`
- **Production**: `log_level: "info"`, `tracing_enabled: true`
- **Troubleshooting**: `log_level: "debug"` temporarily
- **Low disk space**: `log_level: "warn"` or `"error"`

## Authentication Configuration

Controls JWT authentication and authorization for tenant requests.

### Core Options

| Option              | Type    | Default | Description                               |
| ------------------- | ------- | ------- | ----------------------------------------- |
| `jwks_cache_ttl`    | integer | `300`   | JWKS cache TTL (seconds)                  |
| `replay_protection` | boolean | `false` | Enable replay protection (requires Redis) |
| `require_jti`       | boolean | `false` | Require JTI claim in tokens               |
| `jwks_url`          | string  | `""`    | JWKS URL for tenant authentication        |

> **Note**: JWT algorithms are hardcoded to EdDSA and RS256 for security and cannot be configured.
>
> **Note**: The JWT audience is hardcoded to `https://api.inferadb.com` per RFC 8725 best practices.
> The audience identifies the InferaDB Server API as the intended recipient, not a specific endpoint.
> This value must match the audience set by the Management API when generating tokens.

### Management API Integration

| Option                              | Type    | Default | Description                                       |
| ----------------------------------- | ------- | ------- | ------------------------------------------------- |
| `management_api_timeout_ms`         | integer | `5000`  | Timeout for management API calls (milliseconds)   |
| `management_cache_ttl`              | integer | `300`   | Cache TTL for org/vault lookups (seconds)         |
| `cert_cache_ttl`                    | integer | `900`   | Cache TTL for client certificates (seconds)       |
| `management_verify_vault_ownership` | boolean | `true`  | Verify vault ownership against management API     |
| `management_verify_org_status`      | boolean | `true`  | Verify organization status against management API |

### OAuth/OIDC Configuration

| Option                     | Type              | Default | Description               |
| -------------------------- | ----------------- | ------- | ------------------------- |
| `oauth_enabled`            | boolean           | `false` | Enable OAuth validation   |
| `oidc_discovery_url`       | string (optional) | `null`  | OIDC discovery endpoint   |
| `oidc_client_id`           | string (optional) | `null`  | OIDC client ID            |
| `oidc_client_secret`       | string (optional) | `null`  | OIDC client secret        |
| `oidc_discovery_cache_ttl` | integer           | `86400` | OIDC cache TTL (24 hours) |

### Security Options

| Option                  | Type               | Default | Description                     |
| ----------------------- | ------------------ | ------- | ------------------------------- |
| `clock_skew_seconds`    | integer (optional) | `60`    | Clock skew tolerance            |
| `max_token_age_seconds` | integer (optional) | `86400` | Max token age (24 hours)        |
| `redis_url`             | string (optional)  | `null`  | Redis URL for replay protection |

### Examples

**Development** (minimal config):

```yaml
auth:
  jwks_cache_ttl: 300
```

**Production** (full validation):

```yaml
auth:
  jwks_cache_ttl: 300
  replay_protection: true
  require_jti: true
  redis_url: "redis://localhost:6379"
  clock_skew_seconds: 30
  max_token_age_seconds: 3600
  management_verify_vault_ownership: true
  management_verify_org_status: true
```

### Environment Variables

```bash
# Core authentication
export INFERADB__AUTH__JWKS_CACHE_TTL=300

# Management API integration
export INFERADB__AUTH__MANAGEMENT_API_TIMEOUT_MS=5000
export INFERADB__AUTH__MANAGEMENT_CACHE_TTL=300
export INFERADB__AUTH__CERT_CACHE_TTL=900

# Replay protection
export INFERADB__AUTH__REPLAY_PROTECTION=true
export INFERADB__AUTH__REDIS_URL="redis://localhost:6379"
```

## Identity Configuration

Controls server identity for service-to-service authentication.

### Options

| Option            | Type              | Default | Description                                                   |
| ----------------- | ----------------- | ------- | ------------------------------------------------------------- |
| `private_key_pem` | string (optional) | `null`  | Ed25519 private key in PEM format (auto-generated if not set) |

### Example

```yaml
identity:
  private_key_pem: "${SERVER_PRIVATE_KEY}"
```

Or with no configuration (all values auto-generated):

```yaml
identity: {}
```

### Environment Variables

```bash
export INFERADB__IDENTITY__PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Recommendations

- In production, always provide `private_key_pem` rather than relying on auto-generation
- Use Kubernetes secrets or a secret manager for the private key
- The `kid` is deterministically derived from the public key (RFC 7638), so it remains consistent when using the same private key

## Discovery Configuration

Controls service discovery for multi-node deployments.

### Options

| Option                          | Type    | Default | Description                         |
| ------------------------------- | ------- | ------- | ----------------------------------- |
| `mode`                          | object  | `none`  | Discovery mode configuration        |
| `cache_ttl`                     | integer | `300`   | Cache TTL for discovered endpoints (seconds)  |
| `enable_health_check`           | boolean | `false` | Enable health checking of endpoints |
| `health_check_interval`         | integer | `30`    | Health check interval (seconds)     |

### Discovery Modes

#### None (Default)

Direct connection to a single service URL:

```yaml
discovery:
  mode:
    type: none
```

#### Kubernetes

Discover pod IPs via Kubernetes service:

```yaml
discovery:
  mode:
    type: kubernetes
  cache_ttl: 30
  enable_health_check: true
  health_check_interval: 10
```

#### Tailscale

Multi-region discovery via Tailscale mesh:

```yaml
discovery:
  mode:
    type: tailscale
    local_cluster: "us-west-1"
    remote_clusters:
      - name: "eu-west-1"
        tailscale_domain: "eu-west-1.ts.net"
        service_name: "inferadb-server"
        port: 8082
      - name: "ap-southeast-1"
        tailscale_domain: "ap-southeast-1.ts.net"
        service_name: "inferadb-server"
        port: 8082
  cache_ttl: 60
```

### Environment Variables

```bash
export INFERADB__DISCOVERY__CACHE_TTL=30
export INFERADB__DISCOVERY__ENABLE_HEALTH_CHECK=true
export INFERADB__DISCOVERY__HEALTH_CHECK_INTERVAL=10
```

## Management Service Configuration

Controls connection to the InferaDB Management API for JWKS and tenant validation.

### Options

| Option          | Type    | Default                   | Description                      |
| --------------- | ------- | ------------------------- | -------------------------------- |
| `service_url`   | string  | `"http://localhost:9092"` | Management service URL           |
| `internal_port` | integer | `9092`                    | Management service internal port |

### Examples

**Development**:

```yaml
management_service:
  service_url: "http://localhost:9092"
  internal_port: 9092
```

**Kubernetes**:

```yaml
management_service:
  service_url: "http://inferadb-management.inferadb:9092"
  internal_port: 9092
```

### Environment Variables

```bash
export INFERADB__MANAGEMENT_SERVICE__SERVICE_URL="http://inferadb-management.inferadb:9092"
export INFERADB__MANAGEMENT_SERVICE__INTERNAL_PORT=9092
```

## Configuration Profiles

### Development Profile

Optimized for local development:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 8081
  internal_host: "0.0.0.0"
  internal_port: 8082
  worker_threads: 2

storage:
  backend: "memory"

cache:
  enabled: true
  max_capacity: 1000
  ttl: 60

observability:
  log_level: "debug"
  metrics_enabled: true
  tracing_enabled: false

auth: {}

identity: {}

discovery:
  mode:
    type: none

management_service:
  service_url: "http://localhost:9092"
```

### Production Profile

Optimized for production deployment:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 8081
  internal_host: "0.0.0.0"
  internal_port: 8082
  worker_threads: 8

storage:
  backend: "foundationdb"
  fdb_cluster_file: "/etc/foundationdb/fdb.cluster"

cache:
  enabled: true
  max_capacity: 100000
  ttl: 300

observability:
  log_level: "info"
  metrics_enabled: true
  tracing_enabled: true

auth:
  jwks_cache_ttl: 300
  replay_protection: true
  redis_url: "redis://redis:6379"
  management_verify_vault_ownership: true
  management_verify_org_status: true

identity:
  private_key_pem: "${SERVER_PRIVATE_KEY}"

discovery:
  mode:
    type: kubernetes
  cache_ttl: 30
  enable_health_check: true

management_service:
  service_url: "http://inferadb-management.inferadb:9092"
```

### Testing Profile

Optimized for predictable testing:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 8081
  internal_host: "0.0.0.0"
  internal_port: 8082
  worker_threads: 1

storage:
  backend: "memory"

cache:
  enabled: false

observability:
  log_level: "warn"
  metrics_enabled: false
  tracing_enabled: false

auth: {}

identity: {}

discovery:
  mode:
    type: none

management_service:
  service_url: "http://localhost:9092"
```

## Secrets Management

**Never commit secrets to configuration files.**

### Environment Variables (Recommended)

Use environment variables for sensitive values:

```bash
export INFERADB__AUTH__OIDC_CLIENT_SECRET="secret-value"
export INFERADB__AUTH__REDIS_URL="redis://:password@localhost:6379"
export INFERADB__IDENTITY__PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n..."
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: inferadb-server-secrets
type: Opaque
stringData:
  redis-url: "redis://:password@redis:6379"
  private-key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

```yaml
# In deployment
env:
  - name: INFERADB__AUTH__REDIS_URL
    valueFrom:
      secretKeyRef:
        name: inferadb-server-secrets
        key: redis-url
  - name: INFERADB__IDENTITY__PRIVATE_KEY_PEM
    valueFrom:
      secretKeyRef:
        name: inferadb-server-secrets
        key: private-key
```

### External Secret Managers

**AWS Secrets Manager**:

```bash
export INFERADB__IDENTITY__PRIVATE_KEY_PEM=$(aws secretsmanager get-secret-value \
  --secret-id inferadb/server/private-key \
  --query SecretString --output text)
```

**HashiCorp Vault**:

```bash
export INFERADB__IDENTITY__PRIVATE_KEY_PEM=$(vault kv get \
  -field=private_key secret/inferadb/server)
```

## Validation

InferaDB validates configuration at startup. Invalid configurations fail fast with clear error messages.

### Validation Rules

**Server**:

- `port` must be 1-65535
- `worker_threads` must be > 0

**Storage**:

- `backend` must be `"memory"` or `"foundationdb"`
- `fdb_cluster_file` required when `backend = "foundationdb"`

**Cache**:

- `max_capacity` must be > 0 when enabled
- `ttl` must be > 0

**Observability**:

- `log_level` must be valid: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`

**Authentication**:

- Algorithms are hardcoded to EdDSA and RS256 (not configurable)
- Audience is hardcoded to `https://api.inferadb.com` (not configurable)
- `replay_protection = true` requires `redis_url`
- `clock_skew_seconds > 300` generates warning

**Identity**:

- `private_key_pem` is optional (auto-generated if not set)

**Management Service**:

- `service_url` must start with `http://` or `https://`
- `service_url` must not end with trailing slash

### Example Validation Errors

```text
Error: Invalid storage.backend: 'postgres'. Must be 'memory' or 'foundationdb'
```

```text
Error: storage.fdb_cluster_file is required when using FoundationDB backend
```

```text
Error: Algorithm 'HS256' is forbidden for security reasons
```

```text
Error: replay_protection is enabled but redis_url is not configured
```

```text
Error: management_service.service_url must start with http:// or https://
```

## Best Practices

### Security

1. **Asymmetric algorithms only** - Algorithms are hardcoded to EdDSA and RS256 for security

2. **Enable replay protection in production**

   ```yaml
   auth:
     replay_protection: true
     redis_url: "redis://redis:6379"
   ```

3. **Audience validation** - The JWT audience is hardcoded to `https://api.inferadb.com` per RFC 8725 best practices. This ensures tokens are issued for the InferaDB Server API (not a specific endpoint).

4. **Never commit secrets**
   - Use environment variables
   - Use secret managers
   - Use `.gitignore` for config files with secrets

### Performance

1. **Tune worker threads**

   - CPU-bound: 2x CPU cores
   - I/O-bound: 4-8x CPU cores
   - Benchmark and adjust

2. **Optimize cache settings**

   - Increase `max_capacity` for large datasets
   - Adjust `ttl` based on update frequency
   - Monitor cache hit rate (target >80%)

3. **Use FoundationDB in production**
   - Memory backend doesn't persist
   - FoundationDB provides ACID + replication

### Observability

1. **Enable metrics and tracing**

   ```yaml
   observability:
     metrics_enabled: true
     tracing_enabled: true
   ```

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
   inferadb-server --config config.yaml --validate
   ```

## Deployment Examples

### Docker Compose

```yaml
version: "3.8"
services:
  inferadb-server:
    image: inferadb/server:latest
    ports:
      - "8080:8080"
      - "8081:8081"
      - "8082:8082"
    environment:
      INFERADB__SERVER__HOST: "0.0.0.0"
      INFERADB__SERVER__PORT: "8080"
      INFERADB__SERVER__GRPC_PORT: "8081"
      INFERADB__SERVER__INTERNAL_PORT: "8082"
      INFERADB__STORAGE__BACKEND: "foundationdb"
      INFERADB__STORAGE__FDB_CLUSTER_FILE: "/etc/foundationdb/fdb.cluster"
      INFERADB__MANAGEMENT_SERVICE__SERVICE_URL: "http://management:9092"
    volumes:
      - /etc/foundationdb:/etc/foundationdb:ro
```

### Kubernetes

See [Deployment Guide](deployment.md) for complete Kubernetes manifests.

## Troubleshooting

### Server Won't Start

**Check configuration**:

```bash
inferadb-server --config config.yaml --validate
inferadb-server --config config.yaml 2>&1 | grep ERROR
```

### Port Already in Use

```bash
# Find process
lsof -i :8080

# Change port
export INFERADB__SERVER__PORT=8090
```

### Out of Memory

Reduce cache size:

```yaml
cache:
  max_capacity: 10000
```

### Slow Performance

1. Check cache enabled: `cache.enabled = true`
2. Check cache hit rate: `/metrics` endpoint
3. Increase worker threads for high load

## See Also

- [Authentication Guide](../security/authentication.md) - Detailed authentication setup
- [Deployment Guide](deployment.md) - Production deployment
- [Management Configuration](../../../../management/docs/guides/configuration.md) - Management API configuration
