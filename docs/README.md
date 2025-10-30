# InferaDB Documentation

Welcome to the InferaDB developer documentation. This documentation covers the architecture, implementation, and usage of InferaDB - a high-performance authorization service implementing Relationship-Based Access Control (ReBAC).

## Documentation Index

### Getting Started
- [Architecture Overview](architecture.md) - System design and component overview
- [Quick Start Guide](quickstart.md) - Get up and running with InferaDB

### Core Concepts
- [IPL (Infera Policy Language)](ipl-language.md) - Policy definition language
- [Relationship-Based Access Control](rebac-concepts.md) - ReBAC fundamentals
- [Evaluation Engine](evaluation-engine.md) - How authorization decisions are made

### Components
- **Storage Layer**
  - [Storage Backends Overview](storage-backends.md) - Backend comparison and selection guide
  - [Memory Backend](storage-memory.md) - In-memory storage for development and testing
  - [FoundationDB Backend](storage-foundationdb.md) - Production-ready distributed storage
- [Policy Evaluation](evaluation-engine.md) - Graph traversal and decision making
- [WASM Integration](wasm-integration.md) - Custom policy modules with WebAssembly
- [Caching System](caching.md) - Intelligent authorization result caching
- [Query Optimization](query-optimization.md) - Parallel evaluation and planning
- [Revision Tokens](revision-tokens.md) - Snapshot consistency with Zookies
- [Multi-Region Replication](replication.md) - Active-active replication and conflict resolution

### APIs
- [REST API Reference](api-rest.md) - HTTP/JSON API endpoints
- [gRPC API Reference](api-grpc.md) - High-performance gRPC interface

### Development
- [Building from Source](building.md) - Development setup and build instructions
- [Testing Guide](testing.md) - Running tests and writing new tests
- [Contributing](../CONTRIBUTING.md) - Contribution guidelines

### Operations
- [Configuration](configuration.md) - Configuration options and tuning
- [Observability](observability.md) - Metrics, tracing, and logging
- [Service Level Objectives](slos.md) - SLO definitions and error budget policy
- [Prometheus Alerts](../prometheus/README.md) - Prometheus alerting deployment and runbooks
- [Grafana Dashboards](../grafana/README.md) - Monitoring dashboard installation and usage
- [Authentication](../AUTHENTICATION.md) - Authentication implementation guide

### Security
- [Security Audit Checklist](../SECURITY.md) - Comprehensive security audit guidelines
- [Production Hardening](PRODUCTION_HARDENING.md) - Production deployment security checklist
- [Penetration Testing Guide](PENTEST.md) - Security testing procedures
- [Rate Limiting](RATE_LIMITING.md) - Rate limiting recommendations

## Project Status

InferaDB is under active development. Current implementation status:

✅ **Completed:**
- IPL parser and schema validation
- In-memory storage backend with MVCC and revision tracking
- FoundationDB storage backend with distributed transactions
- Storage abstraction layer with flexible backend selection
- Policy evaluation engine with all relation types (union, intersection, exclusion, computed usersets)
- REST and gRPC APIs with authentication
- **Authentication & Authorization**:
  - Private-Key JWT (RFC 7523) for tenant SDK/CLI authentication
  - OAuth 2.0 Bearer Token validation with OIDC discovery
  - Internal Service JWT for control plane authentication
  - JWKS caching with stale-while-revalidate pattern
  - Comprehensive audit logging (JSON structured events)
  - gRPC interceptor-based authentication middleware
- **Multi-Region Replication**:
  - Change feed for real-time change propagation
  - Three replication strategies (ActiveActive, PrimaryReplica, MultiMaster)
  - Four conflict resolution strategies (LWW, SourcePriority, InsertWins, Custom)
  - Region-aware routing with automatic failover
  - Batched replication with retry logic and exponential backoff
  - 10 Prometheus metrics for monitoring replication health
  - Comprehensive testing (70 tests covering all scenarios)
- **Observability**:
  - Prometheus metrics (28 total: 18 auth + 10 replication)
  - OpenTelemetry distributed tracing with semantic conventions
  - Structured audit logging for security events
  - Comprehensive metrics documentation with example queries
  - Service Level Objectives (8 SLOs with measurable targets)
  - Production-ready Prometheus alerting rules (50+ alerts)
  - Grafana dashboards (5 dashboards: overview, performance, replication, errors, cache)
- WASM module integration with sandboxing
- Intelligent caching system with TTL and LRU eviction
- Query optimization infrastructure with parallel evaluation
- Revision tokens for snapshot consistency
- Comprehensive security testing (fuzzing, sandbox isolation)
- Property-based testing with proptest

📋 **Planned:**
- Production deployment tools
- Client SDKs with authentication support

## Quick Links

- [GitHub Repository](https://github.com/your-org/inferadb)
- [Issue Tracker](https://github.com/your-org/inferadb/issues)
- [Project Plan](../PLAN.md)

## Support

For questions, issues, or contributions, please see our [Contributing Guide](../CONTRIBUTING.md).
