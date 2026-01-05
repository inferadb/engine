# InferaDB Development Commands

## System: Darwin (macOS)

## Setup & Environment
```bash
make setup                    # One-time development environment setup (installs tools, fetches deps)
mise trust && mise install    # Alternative: manual tool installation via mise
```

## Running the Engine
```bash
make dev                      # Start dev server with auto-reload (cargo watch)
make run                      # Run engine in debug mode
cargo run --bin inferadb-engine  # Direct cargo command
```

## Building
```bash
make build                    # Debug build
make release                  # Release build (optimized)
cargo build --release --workspace  # Direct cargo command
```

## Testing
```bash
make test                     # Run unit tests (cargo nextest)
make test-integration         # Run integration tests
make test-fdb                 # Run FoundationDB integration tests (requires Docker)
make test-aws                 # Run AWS Secrets Manager tests (requires Docker)
make test-gcp                 # Run GCP Secret Manager tests (requires Docker)
make test-azure               # Run Azure Key Vault tests (requires Docker)
make coverage                 # Generate code coverage report
```

## Code Quality
```bash
make check                    # Run all quality checks (format, lint, audit)
make format                   # Format code (cargo +nightly fmt)
make lint                     # Run clippy linter
make audit                    # Run security audit
make deny                     # Check dependencies with cargo-deny
make fix                      # Auto-fix clippy warnings
```

## Benchmarks & Analysis
```bash
make bench                    # Run benchmarks
make doc                      # Generate documentation
make tree                     # Show dependency tree
make outdated                 # Check for outdated dependencies
make bloat                    # Analyze binary size (requires cargo-bloat)
```

## Docker & Kubernetes
```bash
make docker-build             # Build Docker image
make docker-run               # Run Docker container
make k8s-deploy               # Deploy to local Kubernetes
make k8s-delete               # Delete from Kubernetes
```

## Cleanup
```bash
make clean                    # Clean build artifacts
make reset                    # Full reset of dev environment (Docker, cargo, etc.)
```

## CI Simulation
```bash
make ci                       # Simulate full CI pipeline locally
```

## Unix Utilities (Darwin/macOS)
Standard BSD variants of common utilities:
- `ls`, `cd`, `pwd` - Directory navigation
- `grep` - Search (note: BSD grep, not GNU)
- `find` - File search (note: BSD find syntax)
- `git` - Version control
- `docker` - Container management
- `kubectl` - Kubernetes CLI
