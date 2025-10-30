# Configuration Reference

Complete reference for InferaDB configuration options.

## Table of Contents

- [Overview](#overview)
- [Configuration File Format](#configuration-file-format)
- [Environment Variables](#environment-variables)
- [Server Configuration](#server-configuration)
- [Storage Configuration](#storage-configuration)
- [Cache Configuration](#cache-configuration)
- [Observability Configuration](#observability-configuration)
- [Authentication Configuration](#authentication-configuration)
- [Secrets Management](#secrets-management)
- [Hot Reload](#hot-reload)
- [Examples](#examples)
- [Best Practices](#best-practices)

## Overview

InferaDB supports configuration through multiple sources with the following precedence (highest to lowest):

1. Environment variables (highest)
2. Configuration file
3. Default values (lowest)

Configuration can be provided in TOML format, and environment variables use the `INFERA__` prefix with `__` as the separator.

## Configuration File Format

Configuration files should be in TOML format. By default, InferaDB looks for `config.toml` in the current directory.

```toml
[server]
host = "127.0.0.1"
port = 8080
worker_threads = 4
rate_limiting_enabled = true

[store]
backend = "memory"
connection_string = ""

[cache]
enabled = true
max_capacity = 10000
ttl_seconds = 300

[observability]
log_level = "info"
metrics_enabled = true
tracing_enabled = true

[auth]
enabled = false
# ... see Authentication Configuration section for full options
```

## Environment Variables

Environment variables override configuration file values. Use the `INFERA__` prefix and `__` as a separator for nested keys:

```bash
# Server configuration
export INFERA__SERVER__HOST="0.0.0.0"
export INFERA__SERVER__PORT="9090"
export INFERA__SERVER__WORKER_THREADS="8"

# Store configuration
export INFERA__STORE__BACKEND="foundationdb"
export INFERA__STORE__CONNECTION_STRING="fdb.cluster"

# Cache configuration
export INFERA__CACHE__ENABLED="true"
export INFERA__CACHE__MAX_CAPACITY="50000"

# Auth configuration
export INFERA__AUTH__ENABLED="true"
export INFERA__AUTH__JWKS_URL="https://auth.example.com/.well-known/jwks.json"
```

## Server Configuration

Controls the HTTP/gRPC server behavior.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | `"127.0.0.1"` | Bind address for the server |
| `port` | integer | `8080` | Port to listen on |
| `worker_threads` | integer | CPU count | Number of Tokio worker threads |
| `rate_limiting_enabled` | boolean | `true` | Enable rate limiting middleware |

### Example

```toml
[server]
host = "0.0.0.0"  # Listen on all interfaces
port = 8080
worker_threads = 8  # Use 8 threads regardless of CPU count
rate_limiting_enabled = true
```

### Environment Variables

```bash
export INFERA__SERVER__HOST="0.0.0.0"
export INFERA__SERVER__PORT="8080"
export INFERA__SERVER__WORKER_THREADS="8"
export INFERA__SERVER__RATE_LIMITING_ENABLED="true"
```

### Validation

- `port` must be between 1 and 65535
- `worker_threads` must be greater than 0
- `host` must be a valid IP address or hostname

## Storage Configuration

Controls the tuple storage backend.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backend` | string | `"memory"` | Storage backend: `"memory"` or `"foundationdb"` |
| `connection_string` | string (optional) | `null` | Connection string for FoundationDB cluster file path |

### Example

#### In-Memory Storage (Development)

```toml
[store]
backend = "memory"
```

#### FoundationDB Storage (Production)

```toml
[store]
backend = "foundationdb"
connection_string = "/etc/foundationdb/fdb.cluster"
```

### Environment Variables

```bash
export INFERA__STORE__BACKEND="foundationdb"
export INFERA__STORE__CONNECTION_STRING="/etc/foundationdb/fdb.cluster"
```

### Validation

- `backend` must be one of: `"memory"`, `"foundationdb"`
- `connection_string` is required when `backend = "foundationdb"`

## Cache Configuration

Controls the in-memory check result cache.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable caching |
| `max_capacity` | integer | `10000` | Maximum number of cached entries |
| `ttl_seconds` | integer | `300` | Time-to-live for cache entries (5 minutes) |

### Example

```toml
[cache]
enabled = true
max_capacity = 50000  # Cache up to 50k authorization checks
ttl_seconds = 600     # 10 minute TTL
```

### Environment Variables

```bash
export INFERA__CACHE__ENABLED="true"
export INFERA__CACHE__MAX_CAPACITY="50000"
export INFERA__CACHE__TTL_SECONDS="600"
```

### Validation

- `max_capacity` must be greater than 0 when `enabled = true`
- `ttl_seconds` must be greater than 0

## Observability Configuration

Controls logging, metrics, and tracing.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_level` | string | `"info"` | Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` |
| `metrics_enabled` | boolean | `true` | Enable Prometheus metrics export |
| `tracing_enabled` | boolean | `true` | Enable OpenTelemetry distributed tracing |

### Example

```toml
[observability]
log_level = "debug"  # Verbose logging for development
metrics_enabled = true
tracing_enabled = true
```

### Environment Variables

```bash
export INFERA__OBSERVABILITY__LOG_LEVEL="debug"
export INFERA__OBSERVABILITY__METRICS_ENABLED="true"
export INFERA__OBSERVABILITY__TRACING_ENABLED="true"
```

### Validation

- `log_level` must be one of: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`

## Authentication Configuration

Controls JWT authentication, OAuth, and authorization.

### Core Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable authentication (disable for local development only) |
| `jwks_cache_ttl` | integer | `300` | JWKS cache TTL in seconds |
| `accepted_algorithms` | array | `["EdDSA", "RS256"]` | Accepted JWT signature algorithms |
| `enforce_audience` | boolean | `true` | Enforce audience claim validation |
| `audience` | string | `"https://api.inferadb.com/evaluate"` | Expected audience value |
| `allowed_audiences` | array | `["https://api.inferadb.com/evaluate"]` | List of allowed audience values |
| `enforce_scopes` | boolean | `true` | Enforce scope-based authorization |
| `required_scopes` | array | `[]` | Required scopes for API access |
| `replay_protection` | boolean | `false` | Enable replay attack protection (requires Redis) |
| `require_jti` | boolean | `false` | Require JTI claim in all tokens |

### JWKS Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `jwks_base_url` | string | `"https://auth.inferadb.com/.well-known"` | Base URL for JWKS discovery |
| `jwks_url` | string | `""` | Direct JWKS endpoint URL (alternative to `jwks_base_url`) |

### OAuth Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `oauth_enabled` | boolean | `false` | Enable OAuth 2.0 token introspection |
| `oidc_discovery_url` | string (optional) | `null` | OIDC discovery endpoint |
| `oidc_client_id` | string (optional) | `null` | OIDC client ID |
| `oidc_client_secret` | string (optional) | `null` | OIDC client secret |
| `oidc_discovery_cache_ttl` | integer | `86400` | OIDC discovery cache TTL (24 hours) |
| `introspection_url` | string (optional) | `null` | OAuth introspection endpoint |
| `introspection_cache_ttl` | integer | `60` | Introspection result cache TTL (1 minute) |
| `oauth_introspection_endpoint` | string (optional) | `null` | Legacy introspection endpoint |
| `oauth_introspection_client_id` | string (optional) | `null` | Legacy client ID |
| `oauth_introspection_client_secret` | string (optional) | `null` | Legacy client secret |

### Internal Service JWT

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `internal_jwks_path` | string (optional) | `null` | Path to internal JWKS file |
| `internal_jwks_env` | string (optional) | `"INFERADB_INTERNAL_JWKS"` | Environment variable containing internal JWKS |
| `internal_issuer` | string | `"https://internal.inferadb.com"` | Expected issuer for internal JWTs |
| `internal_audience` | string | `"https://api.inferadb.com/internal"` | Expected audience for internal JWTs |

### Security Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `clock_skew_seconds` | integer (optional) | `60` | Clock skew tolerance for timestamp validation |
| `max_token_age_seconds` | integer (optional) | `86400` | Maximum token age from `iat` to now (24 hours) |
| `issuer_allowlist` | array (optional) | `null` | Only accept tokens from these issuers |
| `issuer_blocklist` | array (optional) | `null` | Reject tokens from these issuers |
| `redis_url` | string (optional) | `null` | Redis URL for replay protection |

### Example - Development (No Auth)

```toml
[auth]
enabled = false
```

### Example - Production with Private-Key JWT

```toml
[auth]
enabled = true
jwks_url = "https://auth.example.com/.well-known/jwks.json"
accepted_algorithms = ["EdDSA", "RS256"]
enforce_audience = true
allowed_audiences = ["https://api.example.com"]
enforce_scopes = true
required_scopes = ["authz:check", "authz:write"]
replay_protection = true
require_jti = true
redis_url = "redis://localhost:6379"
clock_skew_seconds = 30
max_token_age_seconds = 3600
```

### Example - Production with OAuth

```toml
[auth]
enabled = true
oauth_enabled = true
oidc_discovery_url = "https://oauth.example.com/.well-known/openid-configuration"
oidc_client_id = "inferadb-client"
oidc_client_secret = "${OAUTH_CLIENT_SECRET}"  # Secret reference
enforce_audience = true
allowed_audiences = ["inferadb-api"]
```

### Environment Variables

```bash
export INFERA__AUTH__ENABLED="true"
export INFERA__AUTH__JWKS_URL="https://auth.example.com/.well-known/jwks.json"
export INFERA__AUTH__REPLAY_PROTECTION="true"
export INFERA__AUTH__REDIS_URL="redis://localhost:6379"
```

### Validation

- `accepted_algorithms` cannot be empty
- `accepted_algorithms` cannot contain `"none"`, `"HS256"`, `"HS384"`, or `"HS512"` (symmetric algorithms are forbidden)
- `replay_protection = true` requires `redis_url` to be set
- `enforce_audience = true` should have non-empty `allowed_audiences`
- `clock_skew_seconds > 300` will generate a warning

## Secrets Management

InferaDB supports multiple secret providers for sensitive configuration values.

### Secret Reference Syntax

Use `${SECRET_NAME}` in configuration values to reference secrets:

```toml
[auth]
oidc_client_secret = "${OAUTH_CLIENT_SECRET}"
redis_url = "${REDIS_URL}"
```

### Environment Variable Provider

The default provider reads secrets from environment variables:

```bash
export OAUTH_CLIENT_SECRET="my-secret-value"
export REDIS_URL="redis://localhost:6379"
```

### File-Based Provider

Read secrets from individual files (Docker/Kubernetes secrets):

```rust
use infera_config::secrets::FileSecretProvider;

let provider = FileSecretProvider::new("/run/secrets");
// Reads from /run/secrets/OAUTH_CLIENT_SECRET
```

### AWS Secrets Manager (Optional Feature)

Enable with `--features aws-secrets`:

```rust
use infera_config::secrets::AwsSecretsProvider;

let provider = AwsSecretsProvider::new("us-west-2").await?;
let secret = provider.get_async("my-app/oauth/client-secret").await?;
```

### GCP Secret Manager (Optional Feature)

Enable with `--features gcp-secrets`:

```rust
use infera_config::secrets::GcpSecretsProvider;

let provider = GcpSecretsProvider::new("my-project-id").await?;
let secret = provider.get_async("oauth-client-secret").await?;
```

### Azure Key Vault (Optional Feature)

Enable with `--features azure-secrets`:

```rust
use infera_config::secrets::AzureSecretsProvider;

let provider = AzureSecretsProvider::new("https://my-vault.vault.azure.net").await?;
let secret = provider.get_async("oauth-client-secret").await?;
```

### Composite Provider

Chain multiple providers with fallback:

```rust
use infera_config::secrets::{CompositeSecretProvider, EnvSecretProvider, FileSecretProvider};

let provider = CompositeSecretProvider::new()
    .add_provider(Box::new(EnvSecretProvider))  // Try env vars first
    .add_provider(Box::new(FileSecretProvider::new("/run/secrets")));  // Then files
```

## Hot Reload

InferaDB supports reloading configuration without restarting the server.

### File Watch

Automatically reload when the config file changes:

```rust
use std::sync::Arc;
use infera_config::{load, hot_reload::HotReloadHandle};

let config = load("config.toml")?;
let handle = Arc::new(HotReloadHandle::new("config.toml", config));

// Start watching for changes
handle.start_watching()?;
```

### SIGHUP Signal

Send a `SIGHUP` signal to trigger a reload:

```bash
kill -HUP <pid>
```

### Validation and Fallback

- New configuration is validated before applying
- If validation fails, the previous configuration is retained
- Validation errors are logged but don't crash the server
- Use `rollback()` to manually revert to the previous configuration

### Example

```rust
use std::sync::Arc;
use infera_config::{load, hot_reload::HotReloadHandle};

// Initial load
let config = load("config.toml")?;
let handle = Arc::new(HotReloadHandle::new("config.toml", config));

// Start watchers (file changes + SIGHUP)
handle.start_watching()?;

// Get current config (read lock)
let current_config = handle.get().await;

// Manually rollback if needed
if something_went_wrong {
    handle.rollback().await?;
}
```

## Examples

### Minimal Development Configuration

```toml
[server]
port = 8080

[store]
backend = "memory"

[cache]
enabled = true

[observability]
log_level = "debug"

[auth]
enabled = false
```

### Production Configuration with FoundationDB

```toml
[server]
host = "0.0.0.0"
port = 8080
worker_threads = 16
rate_limiting_enabled = true

[store]
backend = "foundationdb"
connection_string = "/etc/foundationdb/fdb.cluster"

[cache]
enabled = true
max_capacity = 100000
ttl_seconds = 600

[observability]
log_level = "info"
metrics_enabled = true
tracing_enabled = true

[auth]
enabled = true
jwks_url = "https://auth.example.com/.well-known/jwks.json"
accepted_algorithms = ["EdDSA", "RS256", "ES256"]
enforce_audience = true
allowed_audiences = ["https://api.example.com"]
enforce_scopes = true
required_scopes = ["authz:check", "authz:write"]
replay_protection = true
require_jti = true
redis_url = "${REDIS_URL}"
clock_skew_seconds = 30
max_token_age_seconds = 3600
```

### Production Configuration with OAuth

```toml
[server]
host = "0.0.0.0"
port = 8080
worker_threads = 16

[store]
backend = "foundationdb"
connection_string = "/etc/foundationdb/fdb.cluster"

[cache]
enabled = true
max_capacity = 100000
ttl_seconds = 600

[observability]
log_level = "info"
metrics_enabled = true
tracing_enabled = true

[auth]
enabled = true
oauth_enabled = true
oidc_discovery_url = "https://oauth.example.com/.well-known/openid-configuration"
oidc_client_id = "inferadb-production"
oidc_client_secret = "${OAUTH_CLIENT_SECRET}"
enforce_audience = true
allowed_audiences = ["inferadb-api"]
enforce_scopes = true
required_scopes = ["authz:read", "authz:write"]
introspection_cache_ttl = 300
oidc_discovery_cache_ttl = 86400
```

## Best Practices

### Security

1. **Never disable authentication in production**
   - Set `auth.enabled = true`
   - Use strong signature algorithms (EdDSA, RS256, ES256)
   - Never use symmetric algorithms (HS256, HS384, HS512)

2. **Use secrets management**
   - Never commit secrets to configuration files
   - Use `${SECRET_NAME}` syntax for sensitive values
   - Use cloud secret managers (AWS/GCP/Azure) in production
   - Rotate secrets regularly

3. **Enable replay protection**
   - Set `auth.replay_protection = true` in production
   - Configure Redis for distributed replay protection
   - Require JTI claims: `auth.require_jti = true`

4. **Validate audiences and issuers**
   - Set `auth.enforce_audience = true`
   - Configure `auth.allowed_audiences` with specific values
   - Use `auth.issuer_allowlist` to restrict trusted issuers
   - Use `auth.issuer_blocklist` to reject specific issuers

5. **Limit clock skew**
   - Keep `auth.clock_skew_seconds <= 60`
   - Sync server clocks with NTP
   - Monitor clock drift

### Performance

1. **Tune worker threads**
   - Set `server.worker_threads` to 2× CPU cores for CPU-bound workloads
   - Set to 4-8× CPU cores for I/O-bound workloads
   - Monitor CPU utilization and adjust

2. **Optimize cache settings**
   - Increase `cache.max_capacity` for large datasets
   - Adjust `cache.ttl_seconds` based on update frequency
   - Monitor cache hit rate (target >80%)

3. **Use FoundationDB in production**
   - In-memory storage doesn't persist across restarts
   - FoundationDB provides ACID transactions and replication
   - Configure FDB cluster appropriately

### Observability

1. **Enable metrics and tracing**
   - Set `observability.metrics_enabled = true`
   - Set `observability.tracing_enabled = true`
   - Export to Prometheus and Jaeger/Zipkin

2. **Choose appropriate log level**
   - Use `"info"` in production
   - Use `"debug"` for troubleshooting
   - Use `"warn"` or `"error"` for production with low disk space

3. **Monitor key metrics**
   - Request latency (p50, p90, p99)
   - Error rate
   - Cache hit rate
   - Active connections
   - CPU and memory utilization

### Operations

1. **Use environment variables for secrets**
   - Easier to rotate without config file changes
   - Better integration with orchestration platforms

2. **Test configuration before deploying**
   - Validate configuration syntax
   - Test authentication with real tokens
   - Load test with production-like data

3. **Use hot reload carefully**
   - Test configuration changes in staging first
   - Monitor logs for validation errors after reload
   - Keep a backup of the previous config
   - Use `rollback()` if issues occur

4. **Document your configuration**
   - Comment configuration files
   - Document non-obvious values
   - Track configuration changes in version control (excluding secrets)

## See Also

- [AUTHENTICATION.md](../AUTHENTICATION.md) - Detailed authentication guide
- [docs/observability.md](observability.md) - Observability configuration and usage
- [docs/storage-backends.md](storage-backends.md) - Storage backend configuration
- [docs/caching.md](caching.md) - Cache configuration and tuning
