# InferaDB Authorization Engine - Project Overview

## Purpose
InferaDB Authorization Engine is a high-performance Relationship-Based Access Control (ReBAC) system with declarative policies, graph evaluation, and sub-millisecond latency. It is inspired by Google Zanzibar and is AuthZEN compliant.

## Key Features
- **High Performance**: Sub-millisecond latency (p50 <1ms cached, 3-5ms uncached), 100K+ RPS throughput
- **Complete API**: Check, Expand, ListResources, ListSubjects, Watch operations
- **Multi-Tenant**: Data isolation via Accounts and Vaults
- **Wildcards**: Support for public resources with `user:*`
- **Observable**: Prometheus, OpenTelemetry, structured logs
- **Storage**: Memory (dev) or Ledger (prod)
- **Extensible**: WASM modules for custom logic

## Tech Stack
- **Language**: Rust (edition 2021, MSRV 1.92)
- **Async Runtime**: Tokio
- **Web Frameworks**: Axum (REST), Tonic (gRPC)
- **Storage Backend**: Ledger (production), In-memory (development)
- **Caching**: Moka
- **Observability**: OpenTelemetry, Prometheus metrics, tracing
- **Authentication**: JWT with JWKS support (jsonwebtoken, ed25519-dalek)
- **Configuration**: YAML-based with environment variable overrides (prefix: `INFERADB__`)
- **Testing**: cargo-nextest, criterion (benchmarks), proptest
- **WASM Runtime**: Wasmtime

## Status
Under active development. Not production-ready.

## License
Business Source License 1.1 (BSL-1.1)
