# InferaDB Policy Decision Engine

**A high-performance, inference-driven authorization runtime built in Rust.**

Implements InferaDB's core reasoning engine, relationship graph store, revision system, and WASM policy module runtime. Designed for millisecond-scale, strongly consistent access checks at global scale.

## Architecture

InferaDB is organized as a modular Rust workspace with the following crates:

- **infera-core** - Policy evaluation engine and IPL (Infera Policy Language) interpreter
- **infera-store** - Storage abstraction with support for multiple backends (FoundationDB, in-memory)
- **infera-wasm** - WebAssembly policy module runtime with sandboxing
- **infera-repl** - Multi-region replication with conflict resolution, change feed, and revision tokens
- **infera-api** - REST and gRPC API layer (AuthZEN-compatible)
- **infera-auth** - Authentication and authorization (JWT, OAuth 2.0, JWKS caching, audit logging)
- **infera-cache** - Caching layer for computed usersets and authorization checks
- **infera-observe** - Observability with tracing, metrics, and structured logging
- **infera-config** - Configuration management supporting files, env vars, and CLI args
- **infera-bin** - Main server binary

## Getting Started

### Prerequisites

- [Mise](https://mise.jdx.dev/)
- Make
- Rust 1.9+

### Setup

```bash
# Trust the configuration
mise trust

# Install Rust and development tools
mise install

# Setup development environment
mise run setup
```

### Development

```bash
# Run the server in development mode
mise run dev

# Run tests
mise run test

# Run linting
mise run lint

# Format code
mise run fmt

# Run all checks (fmt, clippy, test)
mise run check

# Build for release
mise run build-release

# Generate documentation
mise run doc

# Security auditing
mise run audit # cargo-audit
mise run deny # cargo-deny
```

### Configuration

Configuration can be provided via:

1. `config.yaml` file (see [config.yaml](config.yaml))
2. Environment variables (prefix: `INFERA__`)
3. Command-line arguments

Example:

```bash
# Start server on custom port
cargo run --bin inferadb -- --port 9090

# Using environment variables
export INFERA__SERVER__PORT=9090
cargo run --bin inferadb
```

### API Endpoints

- `GET /health` - Health check
- `POST /check` - Authorization check
- `POST /expand` - Expand relation into userset tree
- `POST /write` - Write tuples (coming soon)
- `POST /simulate` - Simulate authorization changes (coming soon)
- `POST /explain` - Explain authorization decision (coming soon)

### Example Check Request

```bash
curl -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "doc:readme",
    "permission": "read"
  }'
```

## Project Structure

```
server/
├── Cargo.toml          # Workspace configuration
├── config.yaml         # Server configuration
├── crates/             # Crate modules
│   ├── infera-core/
│   ├── infera-store/
│   ├── infera-wasm/
│   ├── infera-repl/
│   ├── infera-api/
│   ├── infera-cache/
│   ├── infera-observe/
│   ├── infera-config/
│   └── infera-bin/
└── tests/              # Integration and performance tests
    ├── integration/
    ├── performance/
    └── regression/
```

## Testing

```bash
# Run all tests
cargo test --workspace

# Run with nextest (faster)
mise run test

# Run benchmarks
mise run bench

# Generate code coverage
mise run coverage
```

## Documentation

Comprehensive developer documentation is available in the `docs/` directory:

- **[Quick Start Guide](docs/quickstart.md)** - Get up and running in 5 minutes
- **[Architecture Overview](docs/architecture.md)** - System design and components
- **[IPL Language Guide](docs/ipl-language.md)** - Policy definition language reference
- **[REST API Reference](docs/api-rest.md)** - HTTP/JSON API documentation
- **[Caching System](docs/caching.md)** - Intelligent caching implementation
- **[Multi-Region Replication](docs/replication.md)** - Active-active replication and conflict resolution
- **[Revision Tokens](docs/revision-tokens.md)** - Snapshot consistency with Zookies
- **[Building from Source](docs/building.md)** - Development setup and build instructions

See [docs/README.md](docs/README.md) for the complete documentation index.

## License

InferaDB is made available under the Business Source License 1.1 license. It's free for non-commercial use, and licensable for commercial applications. See our [LICENSE](LICENSE) for additional information.

## Contributing

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) for guidance.
