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

- [API Documentation Hub](../api/README.md) - Complete API documentation portal
- [REST API Explorer (Swagger UI)](../api/swagger-ui.html) - Interactive REST API testing
- [gRPC API Explorer](../api/grpc-explorer.html) - Interactive gRPC API testing
- [REST API Reference](../api/rest.md) - HTTP/JSON API endpoints
- [gRPC API Reference](../api/grpc.md) - High-performance gRPC interface
- [OpenAPI Specification](../api/openapi.yaml) - OpenAPI 3.1 spec

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

## Migration & Comparison

- [Comparison Matrix](comparison-matrix.md) - Feature comparison vs. SpiceDB, OpenFGA, Oso, WorkOS, Amazon
- [Migration Hub](migration/README.md) - Migration guides overview
- [From SpiceDB](migration/from-spicedb.md) - Migrate from SpiceDB to InferaDB
- [From OpenFGA](migration/from-openfga.md) - Migrate from OpenFGA to InferaDB
- [From Oso](migration/from-oso.md) - Migrate from Oso to InferaDB

## Developer Documentation

- [Developer Guide](developers/README.md) - Complete developer documentation
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute to InferaDB
- [Code Style Guidelines](../AGENTS.md) - Code quality standards
- [Testing Guide](guides/testing.md) - Comprehensive testing documentation

## Quick Links

- [GitHub Repository](https://github.com/inferadb/server)
- [Issue Tracker](https://github.com/inferadb/server/issues)
- [Discussions](https://github.com/inferadb/server/discussions)

## Support

For questions, issues, or contributions, please see our [Contributing Guide](../CONTRIBUTING.md) or [Developer Documentation](developers/README.md).
