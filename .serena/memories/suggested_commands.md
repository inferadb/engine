# InferaDB Development Commands

## System: Darwin (macOS)

## Setup & Environment
```bash
mise trust && mise install    # One-time tool installation via mise
cargo fetch                   # Fetch dependencies
```

## Running the Engine
```bash
cargo run --bin inferadb-engine              # Run engine in debug mode
cargo watch -x 'run --bin inferadb-engine'   # Dev server with auto-reload
```

## Building
```bash
cargo build                   # Debug build
cargo build --release         # Release build (optimized)
```

## Testing
```bash
cargo nextest run --lib --workspace          # Run unit tests
cargo nextest run --test '*' --workspace     # Run integration tests
cargo test --doc --all-features              # Run doc tests
./docker/ledger-integration-tests/test.sh    # Ledger integration tests
./docker/aws-integration-tests/test.sh       # AWS Secrets Manager tests
./docker/gcp-integration-tests/test.sh       # GCP Secret Manager tests
./docker/azure-integration-tests/test.sh     # Azure Key Vault tests
cargo llvm-cov --workspace --html            # Generate code coverage report
```

## Code Quality
```bash
cargo +nightly fmt --all                                # Format code
cargo clippy --workspace --all-targets -- -D warnings   # Lint
cargo audit                                             # Security audit
cargo deny check                                        # Dependency checks
cargo clippy --fix --allow-dirty --allow-staged         # Auto-fix warnings
```

## Benchmarks & Analysis
```bash
cargo bench --workspace                      # Run benchmarks
cargo doc --workspace --no-deps              # Generate documentation
cargo tree --workspace                       # Show dependency tree
cargo update --workspace --dry-run           # Check for outdated deps
```

## Docker & Kubernetes
```bash
docker build -t inferadb-engine:dev .        # Build Docker image
docker run -p 8080:8080 -p 8081:8081 inferadb-engine:dev  # Run container
kubectl apply -k k8s/                        # Deploy to Kubernetes
kubectl delete -k k8s/                       # Delete from Kubernetes
```

## Cleanup
```bash
cargo clean                   # Clean build artifacts
```

## Unix Utilities (Darwin/macOS)
Standard BSD variants of common utilities:
- `ls`, `cd`, `pwd` - Directory navigation
- `grep` - Search (note: BSD grep, not GNU)
- `find` - File search (note: BSD find syntax)
- `git` - Version control
- `docker` - Container management
- `kubectl` - Kubernetes CLI
