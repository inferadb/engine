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
- [Storage Layer](storage.md) - Tuple storage and revision management
- [Policy Evaluation](evaluation-engine.md) - Graph traversal and decision making
- [WASM Integration](wasm-integration.md) - Custom policy modules with WebAssembly
- [Caching System](caching.md) - Intelligent authorization result caching
- [Query Optimization](query-optimization.md) - Parallel evaluation and planning
- [Revision Tokens](revision-tokens.md) - Snapshot consistency with Zookies

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

## Project Status

InferaDB is under active development. Current implementation status:

✅ **Completed:**
- IPL parser and schema validation
- In-memory storage backend with revision tracking
- Policy evaluation engine with all relation types
- REST and gRPC APIs
- WASM module integration with sandboxing
- Intelligent caching system
- Query optimization infrastructure
- Revision tokens for snapshot consistency

🚧 **In Progress:**
- FoundationDB storage backend
- Change feed for replication
- Multi-region replication

📋 **Planned:**
- Enhanced observability
- Production deployment tools
- Client SDKs

## Quick Links

- [GitHub Repository](https://github.com/your-org/inferadb)
- [Issue Tracker](https://github.com/your-org/inferadb/issues)
- [Project Plan](../PLAN.md)

## Support

For questions, issues, or contributions, please see our [Contributing Guide](../CONTRIBUTING.md).
