# Configuration

InferaDB can be configured via configuration files, environment variables, or a combination of both. Configuration is loaded at startup and validated before the server starts.

## Configuration File

Create a configuration file in YAML or JSON format:

**`config.yaml`**:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  worker_threads: 4

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
```

**`config.json`**:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "worker_threads": 4
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
  }
}
```

## Environment Variables

All configuration options can be set via environment variables using the `INFERA__` prefix with double underscores as separators:

```bash
# Server configuration
export INFERA__SERVER__HOST="0.0.0.0"
export INFERA__SERVER__PORT=8080
export INFERA__SERVER__WORKER_THREADS=4

# Store configuration
export INFERA__STORE__BACKEND="memory"
export INFERA__STORE__CONNECTION_STRING=""

# Cache configuration
export INFERA__CACHE__ENABLED=true
export INFERA__CACHE__MAX_CAPACITY=10000
export INFERA__CACHE__TTL_SECONDS=300

# Observability configuration
export INFERA__OBSERVABILITY__LOG_LEVEL="info"
export INFERA__OBSERVABILITY__METRICS_ENABLED=true
export INFERA__OBSERVABILITY__TRACING_ENABLED=true
```

**Priority**: Environment variables override file configuration.

## Configuration Options

### Server Configuration

#### `server.host`

**Type**: String
**Default**: `"127.0.0.1"`
**Description**: The host address to bind the server to.

**Examples**:

- `"127.0.0.1"` - Localhost only (development)
- `"0.0.0.0"` - All interfaces (production)
- `"192.168.1.100"` - Specific interface

**Environment Variable**: `INFERA__SERVER__HOST`

#### `server.port`

**Type**: Integer
**Default**: `8080`
**Description**: The port for the REST API server. The gRPC server will use `port + 1`.

**Examples**:

- `8080` - REST API on 8080, gRPC on 8081
- `3000` - REST API on 3000, gRPC on 3001

**Environment Variable**: `INFERA__SERVER__PORT`

#### `server.worker_threads`

**Type**: Integer
**Default**: Number of CPU cores
**Description**: Number of worker threads for the Tokio runtime.

**Recommendations**:

- Development: 2-4 threads
- Production: Number of CPU cores
- High-load: 2x CPU cores

**Environment Variable**: `INFERA__SERVER__WORKER_THREADS`

---

### Store Configuration

#### `store.backend`

**Type**: String
**Default**: `"memory"`
**Description**: The storage backend to use.

**Options**:

- `"memory"` - In-memory storage (default)
- `"foundationdb"` - FoundationDB (requires FDB client libraries)

**Environment Variable**: `INFERA__STORE__BACKEND`

**See Also**: [Storage Backends](storage-backends.md)

#### `store.connection_string`

**Type**: String (optional)
**Default**: `null`
**Description**: Connection string for the storage backend.

**Examples**:

- Memory: Not used (null)
- FoundationDB: Path to cluster file (e.g., `"/etc/foundationdb/fdb.cluster"`)

**Environment Variable**: `INFERA__STORE__CONNECTION_STRING`

---

### Cache Configuration

#### `cache.enabled`

**Type**: Boolean
**Default**: `true`
**Description**: Enable or disable result caching.

**Recommendations**:

- Development: `true` (for realistic performance)
- Production: `true` (significant performance improvement)
- Testing: `false` (for predictable behavior)

**Environment Variable**: `INFERA__CACHE__ENABLED`

#### `cache.max_capacity`

**Type**: Integer
**Default**: `10000`
**Description**: Maximum number of cached entries.

**Recommendations**:

- Small deployments: 1,000 - 10,000
- Medium deployments: 10,000 - 100,000
- Large deployments: 100,000 - 1,000,000

**Memory Usage**: Approximately 200-500 bytes per entry

- 10,000 entries ≈ 2-5 MB
- 100,000 entries ≈ 20-50 MB
- 1,000,000 entries ≈ 200-500 MB

**Environment Variable**: `INFERA__CACHE__MAX_CAPACITY`

#### `cache.ttl_seconds`

**Type**: Integer
**Default**: `300` (5 minutes)
**Description**: Time-to-live for cached entries in seconds.

**Recommendations**:

- Low-latency workloads: 60-300 seconds (1-5 minutes)
- Standard workloads: 300-600 seconds (5-10 minutes)
- Static data: 3600+ seconds (1+ hour)

**Trade-offs**:

- **Shorter TTL**: More consistent data, higher database load
- **Longer TTL**: Better performance, potentially stale data

**Environment Variable**: `INFERA__CACHE__TTL_SECONDS`

**See Also**: [Caching System](caching.md)

---

### Observability Configuration

#### `observability.log_level`

**Type**: String
**Default**: `"info"`
**Description**: Logging level for the application.

**Options**:

- `"error"` - Errors only
- `"warn"` - Warnings and errors
- `"info"` - Informational, warnings, and errors (recommended)
- `"debug"` - Detailed debugging information
- `"trace"` - Very verbose tracing (not recommended for production)

**Environment Variable**: `INFERA__OBSERVABILITY__LOG_LEVEL`

You can also use the `RUST_LOG` environment variable for more granular control:

```bash
# Set log level per module
export RUST_LOG="infera=debug,infera_api=info,infera_store=warn"
```

#### `observability.metrics_enabled`

**Type**: Boolean
**Default**: `true`
**Description**: Enable Prometheus metrics export.

**Metrics Endpoint**: `http://localhost:8080/metrics`

**Environment Variable**: `INFERA__OBSERVABILITY__METRICS_ENABLED`

**See Also**: [Observability](observability.md)

#### `observability.tracing_enabled`

**Type**: Boolean
**Default**: `true`
**Description**: Enable OpenTelemetry distributed tracing.

**Environment Variable**: `INFERA__OBSERVABILITY__TRACING_ENABLED`

**Additional Configuration** (via environment variables):

- `OTEL_EXPORTER_OTLP_ENDPOINT` - OTLP endpoint (e.g., `http://localhost:4317`)
- `OTEL_SERVICE_NAME` - Service name (default: `inferadb`)

**See Also**: [Observability](observability.md)

---

## Configuration Profiles

### Development

Optimized for local development:

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  worker_threads: 2

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
```

### Production

Optimized for production deployment:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  worker_threads: 8 # Adjust based on CPU cores

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
```

### Testing

Optimized for predictable testing:

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  worker_threads: 1

store:
  backend: "memory"

cache:
  enabled: false # Disable caching for predictable tests

observability:
  log_level: "warn"
  metrics_enabled: false
  tracing_enabled: false
```

## Loading Configuration

### From File

```bash
# Start with config file
inferadb --config config.yaml
```

### From Environment

```bash
# Start with environment variables
export INFERA__SERVER__PORT=3000
export INFERA__STORE__BACKEND="memory"
inferadb
```

### Combined (File + Environment)

Environment variables override file configuration:

```bash
# config.yaml sets port to 8080
# Environment variable overrides to 3000
export INFERA__SERVER__PORT=3000
inferadb --config config.yaml
# Server starts on port 3000
```

## Configuration Validation

InferaDB validates configuration at startup. Invalid configurations will fail fast with clear error messages:

### Example Validation Errors

**Invalid port**:

```
Error: Invalid server port: 99999 (must be between 1 and 65535)
```

**Invalid log level**:

```
Error: Invalid log level: 'invalid' (must be one of: error, warn, info, debug, trace)
```

**Invalid backend**:

```
Error: Unknown storage backend: 'postgres' (supported: memory, foundationdb)
```

**See Also**: [`crates/infera-config/src/validation.rs`](../crates/infera-config/src/validation.rs)

## Secrets Management

Sensitive configuration values (like database passwords) should be managed securely.

### Environment Variables

The simplest approach for secrets:

```bash
export INFERA__STORE__CONNECTION_STRING="fdb://username:password@host:port"
```

### Secret Files

Store secrets in files with restricted permissions:

```bash
# Create secret file with restricted permissions
echo "my-secret-value" > /etc/inferadb/secrets/db_password
chmod 600 /etc/inferadb/secrets/db_password

# Reference in environment
export INFERA__STORE__CONNECTION_STRING="$(cat /etc/inferadb/secrets/db_password)"
```

### External Secret Managers

**Future Support**:

- AWS Secrets Manager
- Google Secret Manager
- HashiCorp Vault
- Azure Key Vault

**See Also**: [`crates/infera-config/src/secrets.rs`](../crates/infera-config/src/secrets.rs)

## Configuration Examples

### Docker Deployment

**docker-compose.yml**:

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
      INFERA__CACHE__MAX_CAPACITY: "50000"
      INFERA__OBSERVABILITY__LOG_LEVEL: "info"
    volumes:
      - /var/foundationdb:/etc/foundationdb
```

### Kubernetes Deployment

**configmap.yaml**:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: inferadb-config
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 8080
      worker_threads: 4
    store:
      backend: "foundationdb"
    cache:
      enabled: true
      max_capacity: 100000
      ttl_seconds: 300
    observability:
      log_level: "info"
      metrics_enabled: true
      tracing_enabled: true
```

**secret.yaml**:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: inferadb-secrets
type: Opaque
stringData:
  connection-string: "fdb://..."
```

**deployment.yaml**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inferadb
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: inferadb
          image: inferadb:latest
          ports:
            - containerPort: 8080
            - containerPort: 8081
          env:
            - name: INFERA__STORE__CONNECTION_STRING
              valueFrom:
                secretKeyRef:
                  name: inferadb-secrets
                  key: connection-string
          volumeMounts:
            - name: config
              mountPath: /etc/inferadb
      volumes:
        - name: config
          configMap:
            name: inferadb-config
```

## Performance Tuning

### Worker Threads

**Rule of thumb**: 1-2x CPU cores

```yaml
server:
  worker_threads: 8 # For 4-8 core machine
```

**Benchmark** to find optimal value:

```bash
# Test with 4 threads
INFERA__SERVER__WORKER_THREADS=4 inferadb &
# Run load test
wrk -t 4 -c 100 -d 30s http://localhost:8080/check

# Test with 8 threads
INFERA__SERVER__WORKER_THREADS=8 inferadb &
# Run load test
wrk -t 8 -c 100 -d 30s http://localhost:8080/check

# Compare results
```

### Cache Configuration

**High-throughput workloads**:

```yaml
cache:
  enabled: true
  max_capacity: 500000 # Large cache
  ttl_seconds: 600 # 10 minutes
```

**Low-latency workloads**:

```yaml
cache:
  enabled: true
  max_capacity: 100000
  ttl_seconds: 60 # 1 minute for freshness
```

### Storage Backend

**Development**: Memory (fastest, zero config)

```yaml
store:
  backend: "memory"
```

**Production**: FoundationDB (distributed, durable)

```yaml
store:
  backend: "foundationdb"
  connection_string: "/etc/foundationdb/fdb.cluster"
```

**See Also**: [Storage Backends](storage-backends.md)

## Troubleshooting

### Server Won't Start

**Check configuration**:

```bash
# Validate configuration
inferadb --config config.yaml --validate

# Check logs
inferadb --config config.yaml 2>&1 | grep ERROR
```

### Port Already in Use

**Error**: `Address already in use`

**Solution**: Change port or kill existing process:

```bash
# Find process using port 8080
lsof -i :8080

# Kill process
kill -9 <PID>

# Or change port
export INFERA__SERVER__PORT=8081
```

### Out of Memory

**Symptom**: Server crashes or becomes unresponsive

**Solution**: Reduce cache size:

```yaml
cache:
  max_capacity: 10000 # Reduce from 100000
```

### Slow Performance

**Check**:

1. Cache enabled: `cache.enabled = true`
2. Cache hit rate: Check `/metrics` endpoint
3. Worker threads: Increase for high load

**Optimize**:

```yaml
server:
  worker_threads: 16 # Increase for high load

cache:
  max_capacity: 200000 # Larger cache
```

## Best Practices

### 1. Use Configuration Files for Defaults

Store non-sensitive configuration in files:

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8080
```

### 2. Use Environment Variables for Overrides

Override specific values with environment variables:

```bash
export INFERA__SERVER__PORT=3000  # Override port
```

### 3. Never Commit Secrets

Use environment variables or secret managers:

```bash
# Good
export INFERA__STORE__CONNECTION_STRING="..."

# Bad
# config.yaml:
# store:
#   connection_string: "secret-password-here"  # Don't do this!
```

### 4. Validate Before Deploying

Test configuration before production deployment:

```bash
inferadb --config config.yaml --validate
```

### 5. Monitor Configuration

Track configuration changes in version control:

```bash
git add config.yaml
git commit -m "Update cache size to 100000"
```

## Next Steps

- [Observability](observability.md) - Configure metrics and tracing
- [Storage Backends](storage-backends.md) - Choose and configure storage
- [Caching System](caching.md) - Optimize cache configuration
- [Building from Source](building.md) - Build and run InferaDB
