# InferaDB Codebase Structure

## Workspace Layout
```
engine/
├── crates/                    # Rust workspace crates
├── docs/                      # User documentation
├── tests/                     # Integration tests
├── api/                       # OpenAPI/Proto API definitions
├── proto/                     # Protobuf definitions (git submodule)
├── docker/                    # Docker-related files and integration tests
├── k8s/                       # Kubernetes manifests
├── helm/                      # Helm charts
├── terraform/                 # Terraform modules (AWS, etc.)
├── grafana/                   # Grafana dashboards
├── prometheus/                # Prometheus configuration
├── scripts/                   # Development scripts
└── .github/                   # GitHub Actions workflows
```

## Crate Architecture

### Main Binary
- `inferadb-engine` - Binary entrypoint, server initialization

### API Layer
- `inferadb-engine-api` - REST (Axum) and gRPC (Tonic) endpoints

### Core Logic
- `inferadb-engine-core` - Policy evaluation engine, IPL interpreter
- `inferadb-engine-wasm` - WebAssembly module execution

### Infrastructure
- `inferadb-engine-store` - Storage abstraction layer
- `inferadb-engine-cache` - Moka-based result caching
- `inferadb-engine-config` - YAML configuration loading
- `inferadb-engine-observe` - Metrics, tracing, OpenTelemetry
- `inferadb-engine-discovery` - Service mesh/discovery integration
- `inferadb-engine-fdb-shared` - FoundationDB shared utilities

### Security
- `inferadb-engine-auth` - JWT validation, JWKS, authentication

### Supporting
- `inferadb-engine-types` - Shared type definitions
- `inferadb-engine-const` - Constants and static values
- `inferadb-engine-control-client` - Control plane client
- `inferadb-engine-test-fixtures` - Test utilities and fixtures

## Dependency Flow
```
inferadb-engine (binary)
    └── inferadb-engine-api
            ├── inferadb-engine-core
            │       ├── inferadb-engine-store
            │       └── inferadb-engine-cache
            ├── inferadb-engine-auth
            ├── inferadb-engine-config
            └── inferadb-engine-observe
```

## Key Files
- `Cargo.toml` - Workspace definition and shared dependencies
- `config.yaml` - Default development configuration
- `config.integration.yaml` - Integration test configuration
- `config.production.yaml` - Production configuration template
- `concept.ipl` - Example IPL policy file
- `.rustfmt.toml` - Code formatting configuration
- `rust-toolchain.toml` - Rust toolchain specification
- `.mise.toml` - Mise tool management configuration
