# InferaDB Documentation

Welcome to the InferaDB developer documentation. This documentation covers the architecture, implementation, and usage of InferaDB - a high-performance authorization service implementing Relationship-Based Access Control (ReBAC).

## Getting Started

- [Quick Start Guide](quickstart.md) - Get up and running quickly
- [Architecture Overview](architecture.md) - System design and components

## User Guides

- [Building from Source](guides/building.md) - Development setup and build instructions
- [Configuration](guides/configuration.md) - Configuration options and environment variables
- [Deployment](guides/deployment.md) - Production deployment guide
- [Testing](guides/testing.md) - Running and writing tests

## API Reference

- [REST API](api/rest.md) - HTTP/JSON API endpoints
- [gRPC API](api/grpc.md) - High-performance gRPC interface

## Core Concepts

- [Evaluation Engine](core/evaluation.md) - How authorization decisions are made
- [IPL Language](core/ipl.md) - Infera Policy Language syntax
- [Caching System](core/caching.md) - Authorization result caching
- [Revision Tokens](core/revisions.md) - Snapshot consistency with Zookies

## Storage Backends

- [Storage Overview](storage/overview.md) - Backend comparison and selection
- [Memory Backend](storage/memory.md) - In-memory storage for development
- [FoundationDB Backend](storage/foundationdb.md) - Production distributed storage

## Operations & Monitoring

- [Observability](operations/observability.md) - Metrics, tracing, and logging
- [Performance Baselines](operations/performance.md) - Expected performance characteristics
- [Service Level Objectives](operations/slos.md) - SLO definitions and error budgets
- [Multi-Region Replication](operations/replication.md) - Active-active replication
- [Operational Runbooks](runbooks/README.md) - Day-to-day operations procedures

## Security

- [Authentication](security/authentication.md) - JWT/OAuth authentication guide
- [Production Hardening](security/hardening.md) - Security checklist for production
- [Rate Limiting](security/ratelimiting.md) - Rate limiting recommendations
- [Penetration Testing](security/pentest.md) - Security testing procedures

## Advanced Topics

- [WASM Integration](advanced/wasm.md) - Custom policy modules with WebAssembly

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
  - Replay protection with Redis
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
- **Deployment & Operations**:
  - Multi-stage Docker images with distroless base
  - Kubernetes manifests with security contexts and health probes
  - Helm chart with comprehensive configuration options
  - Health check endpoints (liveness, readiness, startup)
  - Graceful shutdown with connection draining
  - Operational runbooks for scaling, backup/restore, incident response
- WASM module integration with sandboxing
- Intelligent caching system with TTL and LRU eviction
- Query optimization infrastructure with parallel evaluation
- Revision tokens for snapshot consistency
- Comprehensive security testing (fuzzing, sandbox isolation)
- Property-based testing with proptest

📋 **Planned:**

- Client SDKs with authentication support
- Additional storage backend integrations

## Quick Links

- [GitHub Repository](https://github.com/your-org/inferadb)
- [Issue Tracker](https://github.com/your-org/inferadb/issues)
- [Project Plan](../PLAN.md)

## Support

For questions, issues, or contributions, please see our [Contributing Guide](../CONTRIBUTING.md).
