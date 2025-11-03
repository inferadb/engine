# InferaDB Configuration Guide

Complete guide for configuring InferaDB using configuration files and environment variables.

## Table of Contents

- [Overview](#overview)
- [Configuration Methods](#configuration-methods)
- [Server Configuration](#server-configuration)
- [Storage Configuration](#storage-configuration)
- [Cache Configuration](#cache-configuration)
- [Observability Configuration](#observability-configuration)
- [Authentication Configuration](#authentication-configuration)
- [Configuration Profiles](#configuration-profiles)
- [Secrets Management](#secrets-management)
- [Validation](#validation)
- [Best Practices](#best-practices)

## Overview

InferaDB supports configuration through multiple sources with the following precedence (highest to lowest):

1. **Environment variables** (highest priority)
2. **Configuration file**
3. **Default values** (lowest priority)

Configuration files use **YAML or JSON** format, and environment variables use the `INFERA__` prefix with double underscores (`__`) as separators.

## Configuration Methods

### Method 1: Configuration File

Create a `config.yaml` or `config.json` file:

**YAML format** (recommended):

```yaml
server:
    host: "0.0.0.0"
    port: 8080
    worker_threads: 4
    rate_limiting_enabled: true

store:
    backend: "memory"
    connection_string: null

cache:
    enabled: true
    max_capacity: 10000
    ttl_seconds: 300

observability:
    log_level: "info"
    metrics_enabled: true
    tracing_enabled: true

auth:
    enabled: false
```

**JSON format**:

```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "worker_threads": 4,
        "rate_limiting_enabled": true
    },
    "store": {
        "backend": "memory",
        "connection_string": null
    },
    "cache": {
        "enabled": true,
        "max_capacity": 10000,
        "ttl_seconds": 300
    },
    "observability": {
        "log_level": "info",
        "metrics_enabled": true,
        "tracing_enabled": true
    },
    "auth": {
        "enabled": false
    }
}
```

**Load configuration file**:

```bash
inferadb --config config.yaml
```

### Method 2: Environment Variables

All configuration options can be set via environment variables using the `INFERA__` prefix:

```bash
# Server configuration
export INFERA__SERVER__HOST="0.0.0.0"
export INFERA__SERVER__PORT=8080
export INFERA__SERVER__WORKER_THREADS=4
export INFERA__SERVER__RATE_LIMITING_ENABLED=true

# Store configuration
export INFERA__STORE__BACKEND="memory"

# Cache configuration
export INFERA__CACHE__ENABLED=true
export INFERA__CACHE__MAX_CAPACITY=10000
export INFERA__CACHE__TTL_SECONDS=300

# Observability configuration
export INFERA__OBSERVABILITY__LOG_LEVEL="info"
export INFERA__OBSERVABILITY__METRICS_ENABLED=true
export INFERA__OBSERVABILITY__TRACING_ENABLED=true

# Authentication configuration
export INFERA__AUTH__ENABLED=false
```

### Method 3: Combined (File + Environment)

Environment variables override file configuration:

```bash
# config.yaml sets port to 8080
# Environment variable overrides to 3000
export INFERA__SERVER__PORT=3000
inferadb --config config.yaml
# Server starts on port 3000
```

## Server Configuration

Controls HTTP/gRPC server behavior.

### Options

| Option                  | Type    | Default       | Description                         |
| ----------------------- | ------- | ------------- | ----------------------------------- |
| `host`                  | string  | `"127.0.0.1"` | Server bind address                 |
| `port`                  | integer | `8080`        | HTTP server port (gRPC uses port+1) |
| `worker_threads`        | integer | CPU count     | Number of Tokio worker threads      |
| `rate_limiting_enabled` | boolean | `true`        | Enable rate limiting middleware     |

### Examples

**Development** (localhost only):

```yaml
server:
    host: "127.0.0.1"
    port: 8080
    worker_threads: 2
    rate_limiting_enabled: false
```

**Production** (all interfaces):

```yaml
server:
    host: "0.0.0.0"
    port: 8080
    worker_threads: 8
    rate_limiting_enabled: true
```

### Environment Variables

```bash
export INFERA__SERVER__HOST="0.0.0.0"
export INFERA__SERVER__PORT=8080
export INFERA__SERVER__WORKER_THREADS=8
export INFERA__SERVER__RATE_LIMITING_ENABLED=true
```

### Recommendations

- **Development**: `host: "127.0.0.1"`, `worker_threads: 2-4`
- **Production**: `host: "0.0.0.0"`, `worker_threads: 1-2x CPU cores`
- **High-load**: `worker_threads: 2-4x CPU cores`

## Storage Configuration

Controls the tuple storage backend.

### Options

| Option              | Type              | Default    | Description                                     |
| ------------------- | ----------------- | ---------- | ----------------------------------------------- |
| `backend`           | string            | `"memory"` | Storage backend: `"memory"` or `"foundationdb"` |
| `connection_string` | string (optional) | `null`     | Connection string for storage backend           |

### Backend Options

#### Memory Backend (Development)

- **Use case**: Local development, testing
- **Persistence**: None (data lost on restart)
- **Performance**: Fastest
- **Configuration**: No connection string needed

```yaml
store:
    backend: "memory"
```

#### FoundationDB Backend (Production)

- **Use case**: Production deployments
- **Persistence**: ACID transactions, replication
- **Performance**: High throughput, low latency
- **Configuration**: Requires FDB cluster file path

```yaml
store:
    backend: "foundationdb"
    connection_string: "/etc/foundationdb/fdb.cluster"
```

### Environment Variables

```bash
export INFERA__STORE__BACKEND="foundationdb"
export INFERA__STORE__CONNECTION_STRING="/etc/foundationdb/fdb.cluster"
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
| `ttl_seconds`  | integer | `300`   | Cache entry TTL (5 minutes)      |

### Examples

**Small deployment**:

```yaml
cache:
    enabled: true
    max_capacity: 10000
    ttl_seconds: 300
```

**Large deployment**:

```yaml
cache:
    enabled: true
    max_capacity: 1000000
    ttl_seconds: 600
```

**Testing** (disable for predictability):

```yaml
cache:
    enabled: false
```

### Environment Variables

```bash
export INFERA__CACHE__ENABLED=true
export INFERA__CACHE__MAX_CAPACITY=100000
export INFERA__CACHE__TTL_SECONDS=600
```

### Memory Usage

Approximate memory usage per entry: 200-500 bytes

- 10,000 entries ≈ 2-5 MB
- 100,000 entries ≈ 20-50 MB
- 1,000,000 entries ≈ 200-500 MB

### Recommendations

- **Development**: `max_capacity: 1,000-10,000`
- **Production**: `max_capacity: 100,000-1,000,000`
- **Low-latency workloads**: `ttl_seconds: 60-300`
- **Standard workloads**: `ttl_seconds: 300-600`
- **Static data**: `ttl_seconds: 3600+`

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
export INFERA__OBSERVABILITY__LOG_LEVEL="info"
export INFERA__OBSERVABILITY__METRICS_ENABLED=true
export INFERA__OBSERVABILITY__TRACING_ENABLED=true
```

### Additional Configuration

**Granular logging** (via `RUST_LOG`):

```bash
# Set log level per module
export RUST_LOG="infera=debug,infera_api=info,infera_store=warn"
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

Controls JWT authentication, OAuth, and authorization.

For detailed authentication setup, see [Authentication Guide](../security/authentication.md).

### Core Options

| Option                | Type    | Default                                 | Description                               |
| --------------------- | ------- | --------------------------------------- | ----------------------------------------- |
| `enabled`             | boolean | `false`                                 | Enable authentication                     |
| `jwks_cache_ttl`      | integer | `300`                                   | JWKS cache TTL (seconds)                  |
| `accepted_algorithms` | array   | `["EdDSA", "RS256"]`                    | Accepted JWT algorithms                   |
| `enforce_audience`    | boolean | `true`                                  | Enforce audience validation               |
| `audience`            | string  | `"https://api.inferadb.com/evaluate"`   | Expected audience value                   |
| `allowed_audiences`   | array   | `["https://api.inferadb.com/evaluate"]` | Allowed audiences                         |
| `enforce_scopes`      | boolean | `true`                                  | Enforce scope validation                  |
| `required_scopes`     | array   | `[]`                                    | Required scopes for access                |
| `replay_protection`   | boolean | `false`                                 | Enable replay protection (requires Redis) |
| `require_jti`         | boolean | `false`                                 | Require JTI claim in tokens               |

### JWKS Configuration

| Option          | Type   | Default                                   | Description                   |
| --------------- | ------ | ----------------------------------------- | ----------------------------- |
| `jwks_base_url` | string | `"https://auth.inferadb.com/.well-known"` | Base URL for JWKS             |
| `jwks_url`      | string | `""`                                      | Direct JWKS URL (alternative) |

### OAuth/OIDC Configuration

| Option                              | Type              | Default | Description                         |
| ----------------------------------- | ----------------- | ------- | ----------------------------------- |
| `oauth_enabled`                     | boolean           | `false` | Enable OAuth validation             |
| `oidc_discovery_url`                | string (optional) | `null`  | OIDC discovery endpoint             |
| `oidc_client_id`                    | string (optional) | `null`  | OIDC client ID                      |
| `oidc_client_secret`                | string (optional) | `null`  | OIDC client secret                  |
| `oidc_discovery_cache_ttl`          | integer           | `86400` | OIDC cache TTL (24 hours)           |
| `oauth_introspection_endpoint`      | string (optional) | `null`  | OAuth introspection URL             |
| `oauth_introspection_client_id`     | string (optional) | `null`  | Introspection client ID             |
| `oauth_introspection_client_secret` | string (optional) | `null`  | Introspection client secret         |
| `introspection_cache_ttl`           | integer           | `300`   | Introspection cache TTL (5 minutes) |

### Internal Service JWT

| Option               | Type              | Default                    | Description                |
| -------------------- | ----------------- | -------------------------- | -------------------------- |
| `internal_jwks_path` | path (optional)   | `null`                     | Path to internal JWKS file |
| `internal_jwks_env`  | string (optional) | `null`                     | Env var with internal JWKS |
| `internal_issuer`    | string            | `"inferadb-control-plane"` | Internal JWT issuer        |
| `internal_audience`  | string            | `"inferadb-pdp"`           | Internal JWT audience      |

### Security Options

| Option                  | Type               | Default | Description                     |
| ----------------------- | ------------------ | ------- | ------------------------------- |
| `clock_skew_seconds`    | integer (optional) | `60`    | Clock skew tolerance            |
| `max_token_age_seconds` | integer (optional) | `86400` | Max token age (24 hours)        |
| `issuer_allowlist`      | array (optional)   | `null`  | Allowed issuers                 |
| `issuer_blocklist`      | array (optional)   | `null`  | Blocked issuers                 |
| `redis_url`             | string (optional)  | `null`  | Redis URL for replay protection |

### Examples

**Development** (no auth):

```yaml
auth:
    enabled: false
```

**Production** (Private-Key JWT):

```yaml
auth:
    enabled: true
    jwks_base_url: "https://your-domain.com/jwks"
    accepted_algorithms:
        - "EdDSA"
        - "RS256"
        - "ES256"
    enforce_audience: true
    allowed_audiences:
        - "https://api.inferadb.com/evaluate"
    enforce_scopes: true
    required_scopes:
        - "authz:check"
        - "authz:write"
    replay_protection: true
    require_jti: true
    redis_url: "redis://localhost:6379"
    clock_skew_seconds: 30
    max_token_age_seconds: 3600
```

**Production** (OAuth/OIDC):

```yaml
auth:
    enabled: true
    oauth_enabled: true
    oidc_discovery_url: "https://auth.example.com/.well-known/openid-configuration"
    oidc_client_id: "inferadb-server"
    oidc_client_secret: "${OAUTH_CLIENT_SECRET}"
    enforce_audience: true
    allowed_audiences:
        - "inferadb-api"
    enforce_scopes: true
    required_scopes:
        - "authz:check"
        - "authz:write"
```

### Environment Variables

```bash
# Core authentication
export INFERA__AUTH__ENABLED=true
export INFERA__AUTH__JWKS_BASE_URL="https://your-domain.com/jwks"

# OAuth/OIDC
export INFERA__AUTH__OAUTH_ENABLED=true
export INFERA__AUTH__OIDC_DISCOVERY_URL="https://auth.example.com/.well-known/openid-configuration"
export INFERA__AUTH__OIDC_CLIENT_ID="inferadb-server"
export INFERA__AUTH__OIDC_CLIENT_SECRET="secret"

# Replay protection
export INFERA__AUTH__REPLAY_PROTECTION=true
export INFERA__AUTH__REDIS_URL="redis://localhost:6379"
```

## Configuration Profiles

### Development Profile

Optimized for local development:

```yaml
server:
    host: "127.0.0.1"
    port: 8080
    worker_threads: 2
    rate_limiting_enabled: false

store:
    backend: "memory"

cache:
    enabled: true
    max_capacity: 1000
    ttl_seconds: 60

observability:
    log_level: "debug"
    metrics_enabled: true
    tracing_enabled: false

auth:
    enabled: false
```

### Production Profile

Optimized for production deployment:

```yaml
server:
    host: "0.0.0.0"
    port: 8080
    worker_threads: 8
    rate_limiting_enabled: true

store:
    backend: "foundationdb"
    connection_string: "/etc/foundationdb/fdb.cluster"

cache:
    enabled: true
    max_capacity: 100000
    ttl_seconds: 300

observability:
    log_level: "info"
    metrics_enabled: true
    tracing_enabled: true

auth:
    enabled: true
    jwks_base_url: "https://your-domain.com/jwks"
    replay_protection: true
    redis_url: "redis://redis:6379"
```

### Testing Profile

Optimized for predictable testing:

```yaml
server:
    host: "127.0.0.1"
    port: 8080
    worker_threads: 1
    rate_limiting_enabled: false

store:
    backend: "memory"

cache:
    enabled: false # Disable for predictable tests

observability:
    log_level: "warn"
    metrics_enabled: false
    tracing_enabled: false

auth:
    enabled: false
```

## Secrets Management

**⚠️ Never commit secrets to configuration files!**

### Environment Variables (Recommended)

Use environment variables for sensitive values:

```bash
export INFERA__AUTH__OIDC_CLIENT_SECRET="secret-value"
export INFERA__AUTH__REDIS_URL="redis://:password@localhost:6379"
export INFERA__STORE__CONNECTION_STRING="/etc/foundationdb/fdb.cluster"
```

### Docker Secrets

For Docker Swarm or Compose:

```bash
echo "my-secret-value" | docker secret create oauth_client_secret -

docker service create \
  --secret oauth_client_secret \
  --env INFERA__AUTH__OIDC_CLIENT_SECRET_FILE=/run/secrets/oauth_client_secret \
  inferadb:latest
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
    name: inferadb-secrets
type: Opaque
stringData:
    oauth-client-secret: "your-secret-here"
    redis-url: "redis://:password@redis:6379"
```

```yaml
# In deployment
env:
    - name: INFERA__AUTH__OIDC_CLIENT_SECRET
      valueFrom:
          secretKeyRef:
              name: inferadb-secrets
              key: oauth-client-secret
    - name: INFERA__AUTH__REDIS_URL
      valueFrom:
          secretKeyRef:
              name: inferadb-secrets
              key: redis-url
```

### External Secret Managers

**AWS Secrets Manager**:

```bash
export INFERA__AUTH__OIDC_CLIENT_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id inferadb/oauth/client-secret \
  --query SecretString --output text)
```

**HashiCorp Vault**:

```bash
export INFERA__AUTH__OIDC_CLIENT_SECRET=$(vault kv get \
  -field=client_secret secret/inferadb/oauth)
```

**Google Secret Manager**:

```bash
export INFERA__AUTH__OIDC_CLIENT_SECRET=$(gcloud secrets versions access latest \
  --secret=inferadb-oauth-client-secret)
```

## Validation

InferaDB validates configuration at startup. Invalid configurations fail fast with clear error messages.

### Validation Rules

**Server**:

- `port` must be 1-65535
- `worker_threads` must be > 0
- `host` must be a valid IP or hostname

**Store**:

- `backend` must be `"memory"` or `"foundationdb"`
- `connection_string` required when `backend = "foundationdb"`

**Cache**:

- `max_capacity` must be > 0 when enabled
- `ttl_seconds` must be > 0

**Observability**:

- `log_level` must be valid: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`

**Authentication**:

- `accepted_algorithms` cannot be empty
- Cannot accept symmetric algorithms (HS256, HS384, HS512)
- `replay_protection = true` requires `redis_url`
- `enforce_audience = true` should have non-empty `allowed_audiences`
- `clock_skew_seconds > 300` generates warning

### Example Validation Errors

```
Error: Invalid server port: 99999 (must be between 1 and 65535)
```

```
Error: Invalid log level: 'invalid' (must be one of: error, warn, info, debug, trace)
```

```
Error: Unknown storage backend: 'postgres' (supported: memory, foundationdb)
```

```
Error: Replay protection enabled but redis_url not configured
```

## Best Practices

### Security

1. **Enable authentication in production**

    ```yaml
    auth:
        enabled: true
    ```

2. **Use asymmetric algorithms only**

    ```yaml
    auth:
        accepted_algorithms: ["EdDSA", "RS256", "ES256"]
    ```

3. **Enable replay protection**

    ```yaml
    auth:
        replay_protection: true
        redis_url: "redis://redis:6379"
    ```

4. **Validate audiences**

    ```yaml
    auth:
        enforce_audience: true
        allowed_audiences:
            - "https://api.inferadb.com/evaluate"
    ```

5. **Never commit secrets**
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
    - Adjust `ttl_seconds` based on update frequency
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
    inferadb --config config.yaml --validate
    ```

4. **Document configuration changes**
    - Comment config files
    - Track in version control
    - Document non-obvious values

## Deployment Examples

### Docker Compose

```yaml
version: "3.8"
services:
    inferadb:
        image: inferadb:latest
        ports:
            - "8080:8080"
            - "8081:8081"
        environment:
            INFERA__SERVER__HOST: "0.0.0.0"
            INFERA__SERVER__PORT: "8080"
            INFERA__STORE__BACKEND: "foundationdb"
            INFERA__STORE__CONNECTION_STRING: "/etc/foundationdb/fdb.cluster"
            INFERA__AUTH__ENABLED: "true"
            INFERA__AUTH__JWKS_BASE_URL: "https://your-domain.com/jwks"
        volumes:
            - /etc/foundationdb:/etc/foundationdb:ro
```

### Kubernetes

See [Deployment Guide](deployment.md) and [Kubernetes manifests](../k8s/README.md).

## Troubleshooting

### Server Won't Start

**Check configuration**:

```bash
inferadb --config config.yaml --validate
inferadb --config config.yaml 2>&1 | grep ERROR
```

### Port Already in Use

```bash
# Find process
lsof -i :8080

# Change port
export INFERA__SERVER__PORT=8081
```

### Out of Memory

Reduce cache size:

```yaml
cache:
    max_capacity: 10000 # Reduce from larger value
```

### Slow Performance

1. Check cache enabled: `cache.enabled = true`
2. Check cache hit rate: `/metrics` endpoint
3. Increase worker threads for high load

## See Also

- [Authentication Guide](../security/authentication.md) - Detailed authentication setup
- [Deployment Guide](deployment.md) - Production deployment
- [Observability Guide](../operations/observability/README.md) - Metrics and tracing
- [Kubernetes Deployment](../k8s/README.md) - K8s manifests
- [Helm Chart](../../helm/README.md) - Helm deployment
