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
- In-memory storage backend with MVCC and revision tracking
- FoundationDB storage backend with distributed transactions
- Storage abstraction layer with flexible backend selection
- Policy evaluation engine with all relation types (union, intersection, exclusion, computed usersets)
- REST and gRPC APIs
- WASM module integration with sandboxing
- Intelligent caching system with TTL and LRU eviction
- Query optimization infrastructure with parallel evaluation
- Revision tokens for snapshot consistency
- Comprehensive security testing (fuzzing, sandbox isolation)
- Property-based testing with proptest

🚧 **In Progress:**
- Change feed for replication
- Multi-region replication
- Enhanced documentation

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
