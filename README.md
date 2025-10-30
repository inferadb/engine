# InferaDB

**A high-performance authorization engine implementing Relationship-Based Access Control (ReBAC) in Rust.**

InferaDB delivers millisecond-scale authorization decisions at global scale through distributed inference, intelligent caching, and a powerful policy language.

## What Makes InferaDB Special?

- **Blazing Fast**: Sub-10ms authorization checks with intelligent caching
- **Global Scale**: Multi-region replication with active-active deployment
- **Production Ready**: JWT/OAuth authentication, graceful shutdown, health checks
- **Observable**: Prometheus metrics, OpenTelemetry tracing, structured logging
- **ReBAC Native**: First-class relationship traversal and computed usersets
- **Flexible Storage**: Memory backend for dev, FoundationDB for production
- **Extensible**: WASM modules for custom authorization logic

## Quick Start

### Prerequisites

- [Mise](https://mise.jdx.dev/)
- Rust 1.83+

### Get Running in 60 Seconds

```bash
# Clone and setup
git clone https://github.com/inferadb/server inferadb
cd inferadb

# Trust configuration and install dependencies
mise trust && mise install

# Start the server
mise run dev

# Server now running at http://localhost:8080
```

### Make Your First Authorization Check

```bash
curl -X POST http://localhost:8080/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "tuple": {
      "object": "doc:readme",
      "relation": "viewer",
      "subject": "user:alice"
    }
  }'

# Response: {"allowed": true}
```

**→ Continue with the [Quick Start Guide](docs/quickstart.md) for a complete walkthrough**

## Architecture

InferaDB is built as a modular Rust workspace:

```
┌─────────────────────────────────────────────────────────┐
│                     infera-api                           │
│              REST + gRPC API Layer                       │
├─────────────────────────────────────────────────────────┤
│  infera-auth  │  infera-core  │  infera-cache           │
│  JWT/OAuth    │  Evaluation   │  LRU Cache              │
├─────────────────────────────────────────────────────────┤
│  infera-store │  infera-repl  │  infera-wasm            │
│  Storage      │  Replication  │  WASM Runtime           │
├─────────────────────────────────────────────────────────┤
│            infera-observe + infera-config                │
│         Metrics/Tracing + Configuration                  │
└─────────────────────────────────────────────────────────┘
```

**Core Crates:**

- **infera-core** - Policy evaluation engine and IPL interpreter
- **infera-store** - Storage abstraction (Memory, FoundationDB)
- **infera-api** - REST and gRPC APIs with authentication
- **infera-auth** - JWT/OAuth validation, JWKS caching
- **infera-cache** - Intelligent authorization result caching
- **infera-repl** - Multi-region replication with conflict resolution
- **infera-wasm** - WebAssembly policy module runtime
- **infera-observe** - Metrics, tracing, and logging
- **infera-config** - Configuration management

**→ Learn more in the [Architecture Overview](docs/architecture.md)**

## Development Commands

```bash
# Development
mise run dev          # Start server with hot reload
mise run test         # Run all tests
mise run check        # Run fmt, clippy, and tests

# Code Quality
mise run fmt          # Format code
mise run lint         # Run clippy
mise run audit        # Security audit
mise run deny         # License and dependency checks

# Documentation
mise run doc          # Generate API docs
mise run coverage     # Generate code coverage

# Release
mise run build-release  # Optimized production build
```

**→ See [Building from Source](docs/guides/building.md) for detailed setup**

## Configuration

Configure InferaDB using any combination of:

1. **Configuration file** (`config.yaml`)
2. **Environment variables** (`INFERA__SERVER__PORT=8080`)
3. **Command-line arguments** (`--port 8080`)

**Example Production Configuration:**

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  worker_threads: 8

store:
  backend: "foundationdb"
  connection_string: "/etc/foundationdb/fdb.cluster"

cache:
  enabled: true
  max_capacity: 100000
  ttl_seconds: 300

auth:
  enabled: true
  jwks_base_url: "https://your-domain.com/jwks"
  replay_protection: true
  redis_url: "redis://redis:6379"
```

**→ Complete reference: [Configuration Guide](docs/guides/configuration.md)**

## Deployment

InferaDB is production-ready with multiple deployment options:

- **Docker**: Multi-stage builds with distroless base images
- **Kubernetes**: Manifests with security contexts and health probes
- **Helm**: Comprehensive chart with autoscaling and monitoring
- **Terraform**: One-command cloud deployment on AWS and GCP
- **Health Checks**: Liveness, readiness, and startup endpoints
- **Graceful Shutdown**: Connection draining and clean termination

```bash
# Docker
docker run -p 8080:8080 inferadb:latest

# Kubernetes
kubectl apply -k k8s/

# Helm
helm install inferadb ./helm

# Terraform (AWS)
cd terraform/examples/aws-complete && terraform apply

# Terraform (GCP)
cd terraform/examples/gcp-complete && terraform apply
```

**→ Full deployment guide: [Deployment](docs/guides/deployment.md)**
**→ Terraform modules: [terraform/](terraform/)**

## Documentation

Comprehensive documentation organized by topic:

### Getting Started

- [Quick Start Guide](docs/quickstart.md) - Get running in 5 minutes
- [Architecture Overview](docs/architecture.md) - System design and components

### User Guides

- [Building from Source](docs/guides/building.md) - Development setup
- [Configuration](docs/guides/configuration.md) - Configuration reference
- [Deployment](docs/guides/deployment.md) - Production deployment
- [Testing](docs/guides/testing.md) - Testing guide

### API Reference

- [API Documentation Hub](api/README.md) - Complete API portal
- [REST API Explorer (Swagger UI)](api/swagger-ui.html) - Interactive testing
- [gRPC API Explorer](api/grpc-explorer.html) - Interactive gRPC testing
- [REST API](api/rest.md) - HTTP/JSON endpoints
- [gRPC API](api/grpc.md) - High-performance gRPC
- [OpenAPI Spec](api/openapi.yaml) - OpenAPI 3.1 specification

### Core Concepts

- [Evaluation Engine](docs/core/evaluation.md) - How decisions are made
- [IPL Language](docs/core/ipl.md) - Policy definition language
- [Caching](docs/core/caching.md) - Caching system
- [Revision Tokens](docs/core/revisions.md) - Snapshot consistency

### Operations

- [Observability](docs/operations/observability.md) - Metrics and tracing
- [Performance](docs/operations/performance.md) - Performance baselines
- [SLOs](docs/operations/slos.md) - Service level objectives
- [Runbooks](docs/runbooks/README.md) - Operational procedures

### Security

- [Authentication](docs/security/authentication.md) - JWT/OAuth setup
- [Production Hardening](docs/security/hardening.md) - Security checklist
- [Rate Limiting](docs/security/ratelimiting.md) - Rate limiting guide

**→ Browse all documentation: [docs/README.md](docs/README.md)**

## Performance

InferaDB is designed for sub-10ms authorization checks:

| Operation        | p50 Latency | p99 Latency | Throughput |
| ---------------- | ----------- | ----------- | ---------- |
| Check (cached)   | <1ms        | <2ms        | 100K+ RPS  |
| Check (uncached) | 3-5ms       | 8-10ms      | 50K+ RPS   |
| Expand           | 5-15ms      | 20-30ms     | 20K+ RPS   |
| Write            | 2-5ms       | 10-15ms     | 30K+ RPS   |

_Benchmarks: 8-core CPU, memory backend, single region_

**→ Details: [Performance Baselines](docs/operations/performance.md)**

## Contributing

We welcome contributions! Please see:

- [Contributing Guide](CONTRIBUTING.md) - Contribution process and guidelines
- [Developer Documentation](docs/developers/README.md) - Codebase structure and development guide
- [Code Style Guidelines](AGENTS.md) - Code quality standards
- [Issue Tracker](https://github.com/inferadb/server/issues) - Report bugs or request features

## License

InferaDB is made available under the [Business Source License 1.1](LICENSE).

**Free for non-commercial use.** Commercial use requires a license.

---

**Questions?** Open an [issue](https://github.com/inferadb/server/issues) or check the [documentation](docs/README.md).
