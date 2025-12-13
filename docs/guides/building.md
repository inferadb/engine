# Building from Source

This guide covers how to build, test, and develop InferaDB from source.

## Prerequisites

### Required

- **Rust** 1.85 or later

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **Cargo** (comes with Rust)

### Optional

- **Mise** - Task runner and development tool manager

  ```bash
  curl https://mise.run | sh
  ```

- **Docker** - For containerized builds and testing

## Quick Start

### Clone the Repository

```bash
git clone https://github.com/inferadb/server.git
cd inferadb/server
```

### Build

```bash
cargo build
```

This compiles all workspace crates in debug mode.

### Run Tests

```bash
cargo test
```

### Run Benchmarks

```bash
cargo bench
```

## Development Setup

### One-Time Setup with Mise (Recommended)

Mise installs all development tools automatically:

```bash
# Install Mise (if not already installed)
curl https://mise.run | sh

# One-time setup: installs Rust, cargo tools, protobuf
mise trust && mise install

# That's it! Now use standard cargo commands
```

### Standard Development Commands

Use standard cargo commands for daily development:

```bash
# Run tests
cargo test                              # All tests
cargo test --package inferadb-engine-core        # Specific package
cargo nextest run                       # Using nextest (faster)

# Build
cargo build                             # Debug build
cargo build --release                   # Release build
cargo check                             # Check without building

# Code quality
cargo clippy --workspace -- -D warnings # Lint
cargo fmt                               # Format code
cargo audit                             # Security audit

# Development server with auto-reload
cargo watch -x 'run --bin inferadb-engine'

# Benchmarks
cargo bench                             # All benchmarks
cargo bench --package inferadb-engine-core       # Specific package
```

### Make Shortcuts (Optional)

For convenience, use Make for common tasks:

```bash
make help        # Show all available commands
make test        # Run all tests
make check       # Run fmt + clippy + test + audit
make dev         # Start dev server with watch
make ci          # Simulate CI checks locally
```

## Project Structure

```text
server/
├── crates/
│   ├── inferadb-engine-api/      # REST and gRPC APIs
│   ├── inferadb-engine/          # Main binary
│   ├── inferadb-engine-cache/    # Caching layer
│   ├── inferadb-engine-config/   # Configuration
│   ├── inferadb-engine-core/     # Evaluation engine
│   ├── inferadb-engine-observe/  # Observability
│   ├── inferadb-engine-store/    # Storage backends
│   └── inferadb-engine-wasm/     # WASM integration
├── docs/                # Documentation
├── Cargo.toml          # Workspace definition
├── Cargo.lock          # Dependency lock file
└── mise.toml           # Mise task definitions
```

## Build Modes

### Debug Build (Default)

```bash
cargo build
```

- Faster compilation
- Includes debug symbols
- No optimizations
- Use for development

Binary location: `target/debug/inferadb-engine`

### Release Build

```bash
cargo build --release
```

- Slower compilation
- Optimized for performance
- Smaller binary size
- Use for production

Binary location: `target/release/inferadb-engine`

### Profile-Guided Optimization (PGO)

For maximum performance:

```bash
# 1. Build with instrumentation
RUSTFLAGS="-Cprofile-generate=/tmp/pgo-data" cargo build --release

# 2. Run workload to collect profile data
./target/release/inferadb-engine run
# ... run typical workload ...

# 3. Build with profile optimization
llvm-profdata merge -o /tmp/pgo-data/merged.profdata /tmp/pgo-data
RUSTFLAGS="-Cprofile-use=/tmp/pgo-data/merged.profdata" cargo build --release
```

## Testing

### Run All Tests

```bash
cargo test
```

### Run Specific Package Tests

```bash
cargo test --package inferadb-engine-core
cargo test --package inferadb-engine-store
```

### Run Specific Test

```bash
cargo test test_union_evaluation
```

### Run with Output

```bash
cargo test -- --nocapture
```

### Run Ignored Tests

```bash
cargo test -- --ignored
```

### Test Coverage

Using tarpaulin:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage
```

### Integration Tests

```bash
# Run integration tests (when implemented)
cargo test --test integration
```

## Benchmarking

### Run All Benchmarks

```bash
cargo bench
```

### Run Specific Benchmark Suite

```bash
cargo bench --package inferadb-engine-core --bench evaluator
cargo bench --package inferadb-engine-core --bench ipl_parser
cargo bench --package inferadb-engine-core --bench optimizer
```

### Benchmark Comparison

```bash
# Baseline
cargo bench -- --save-baseline main

# Make changes...

# Compare
cargo bench -- --baseline main
```

### Profiling Benchmarks

```bash
# Install flamegraph
cargo install flamegraph

# Profile a benchmark
cargo flamegraph --bench evaluator -- --bench
```

## Linting and Formatting

### Check Formatting

```bash
cargo fmt --check
```

### Format Code

```bash
cargo fmt
```

### Run Clippy

```bash
cargo clippy
```

### Run Clippy with All Features

```bash
cargo clippy --all-features
```

### Fix Clippy Warnings

```bash
cargo clippy --fix
```

## Documentation

### Build Documentation

```bash
cargo doc
```

### Build and Open Documentation

```bash
cargo doc --open
```

### Build Documentation with Private Items

```bash
cargo doc --document-private-items
```

## Dependencies

### Update Dependencies

```bash
cargo update
```

### Check for Outdated Dependencies

```bash
# Install cargo-outdated
cargo install cargo-outdated

# Check outdated dependencies
cargo outdated
```

### Audit Dependencies for Security Issues

InferaDB uses two tools for security auditing:

#### cargo-audit

Checks for known security vulnerabilities in dependencies:

```bash
# Install cargo-audit
cargo install cargo-audit

# Run security audit
cargo audit
```

Configuration: `.cargo/audit.toml`

#### cargo-deny

Comprehensive license and security policy enforcement:

```bash
# Install cargo-deny
cargo install cargo-deny

# Check licenses, advisories, and bans
cargo deny check

# Check only advisories
cargo deny check advisories

# Check only licenses
cargo deny check licenses
```

Configuration: `deny.toml`

See [SECURITY.md](../SECURITY.md) for the complete security audit checklist and [AUTHENTICATION.md](../AUTHENTICATION.md) for authentication security guidelines.

## Building Specific Features

### With FoundationDB Support

```bash
cargo build --features foundationdb
```

### Without Default Features

```bash
cargo build --no-default-features
```

## Cross-Compilation

### For Linux (from macOS)

```bash
# Install target
rustup target add x86_64-unknown-linux-gnu

# Build
cargo build --target x86_64-unknown-linux-gnu
```

### For ARM (e.g., AWS Graviton)

```bash
# Install target
rustup target add aarch64-unknown-linux-gnu

# Build
cargo build --target aarch64-unknown-linux-gnu
```

## Docker Builds

### Build Docker Image

```bash
docker build -t inferadb-engine:latest .
```

### Multi-Stage Build (Optimized)

```dockerfile
# Dockerfile
FROM rust:1.85 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/inferadb-engine /usr/local/bin/
CMD ["inferadb-engine", "run"]
```

### Build and Run

```bash
docker build -t inferadb-engine .
docker run -p 8080:8080 inferadb-engine
```

## Troubleshooting

### Compilation Errors

**Error: linker 'cc' not found**

```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# macOS (install Xcode Command Line Tools)
xcode-select --install
```

**Error: OpenSSL not found**

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev pkg-config

# macOS
brew install openssl
```

### Slow Compilation

1. **Use sccache** (compiler cache):

   ```bash
   cargo install sccache
   export RUSTC_WRAPPER=sccache
   ```

2. **Increase parallel jobs**:

   ```bash
   # Add to ~/.cargo/config.toml
   [build]
   jobs = 8
   ```

3. **Use mold linker** (Linux only):

   ```bash
   # Install mold
   sudo apt-get install mold  # or build from source

   # Add to ~/.cargo/config.toml
   [target.x86_64-unknown-linux-gnu]
   linker = "clang"
   rustflags = ["-C", "link-arg=-fuse-ld=mold"]
   ```

### Test Failures

**Tests hang or timeout**:

- Check for deadlocks in async code
- Increase test timeout: `cargo test -- --test-threads=1`

**Tests fail intermittently**:

- Race condition in tests
- Non-deterministic behavior
- Run with `RUST_TEST_SHUFFLE=1` to detect

### Memory Issues During Build

```bash
# Reduce parallel jobs
cargo build -j 2
```

## Performance Tips

### Faster Incremental Builds

```bash
# Add to ~/.cargo/config.toml
[build]
incremental = true

[profile.dev]
incremental = true
```

### Faster Linking

```bash
# Use lld linker (faster than default)
# Add to .cargo/config.toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
```

### Optimize Build Times

1. Split large crates into smaller ones
2. Use `cargo check` instead of `cargo build` during development
3. Use `cargo clippy` for fast linting
4. Enable sccache for caching compiled dependencies

## IDE Setup

### VS Code

Install extensions:

- rust-analyzer
- CodeLLDB (debugging)
- Even Better TOML
- crates

Settings:

```json
{
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.cargo.features": "all"
}
```

### IntelliJ IDEA / CLion

Install plugins:

- Rust
- TOML

Enable Rust support in settings.

### Vim/Neovim

Use rust-analyzer with LSP client:

```vim
" Using coc.nvim
Plug 'neoclide/coc.nvim', {'branch': 'release'}
Plug 'rust-lang/rust.vim'

" Or using native LSP
Plug 'neovim/nvim-lspconfig'
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - run: cargo test --all-features
      - run: cargo clippy -- -D warnings
      - run: cargo fmt -- --check
```

## Contribution Workflow

1. **Fork and clone** the repository
2. **Create a branch** for your feature
3. **Make changes** and add tests
4. **Run tests**: `cargo test`
5. **Run linter**: `cargo clippy`
6. **Format code**: `cargo fmt`
7. **Commit and push** your changes
8. **Open a pull request**

## Getting Help

- **Documentation**: See `docs/` directory
- **Issues**: <https://github.com/inferadb/server/issues>
- **Discussions**: <https://github.com/inferadb/server/discussions>
- **Discord**: [Community Discord](https://discord.gg/inferadb)
