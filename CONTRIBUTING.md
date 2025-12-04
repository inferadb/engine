# Contributing to InferaDB

Thank you for your interest in contributing to InferaDB! This document provides guidelines and information for contributors.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please be respectful and constructive in all interactions.

## Ways to Contribute

- **Report bugs** - File issues for bugs you encounter
- **Suggest features** - Propose new features or improvements
- **Write documentation** - Improve or add documentation
- **Submit code** - Fix bugs or implement features
- **Review PRs** - Help review pull requests
- **Answer questions** - Help others in discussions

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/inferadb.git
cd inferadb/server

# Add upstream remote
git remote add upstream https://github.com/inferadb/server
```

### 2. Set Up Development Environment

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Mise for tool management
curl https://mise.run | sh

# One-time setup (installs tools and dependencies)
mise trust && mise install

# Build the project
cargo build

# Run tests
cargo test
```

See [Building from Source](docs/guides/building.md) for detailed setup instructions.

### 3. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

## Development Workflow

### Making Changes

1. **Write code** following our style guidelines (see below)
2. **Add tests** for new functionality
3. **Update documentation** if needed
4. **Run tests** to ensure nothing breaks
5. **Format code** using `cargo fmt`
6. **Run linter** using `cargo clippy`

### Before Committing

```bash
# Use standard cargo commands
cargo fmt
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo audit

# Or use Make to run all checks at once
make check  # Runs fmt, clippy, test, audit
make ci     # Simulates CI environment
```

### Commit Messages

Use clear, descriptive commit messages:

```text
feat: add support for WASM policy modules

- Implement WASM host with sandbox
- Add fuel-based execution limits
- Include comprehensive tests
```

Format: `type: subject`

**Types**:

- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `test` - Adding or updating tests
- `refactor` - Code refactoring
- `perf` - Performance improvement
- `chore` - Maintenance tasks

### Submitting a Pull Request

1. **Push your branch**:

   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a pull request** on GitHub

3. **Describe your changes**:
   - What does this PR do?
   - Why is this change needed?
   - How has it been tested?
   - Any breaking changes?

4. **Wait for review** - A maintainer will review your PR

5. **Address feedback** - Make requested changes if needed

6. **Celebrate!** - Once approved, your PR will be merged

## Code Style Guidelines

### Rust Style

We follow the official Rust style guide and enforce it with automated tools:

- Use `mise run fmt` (or `cargo fmt`) to format code
- Use `mise run lint` (or `cargo clippy`) to catch common mistakes
- Write idiomatic Rust code
- Follow guidelines in [AGENTS.md](AGENTS.md) for code quality standards

### Complete Developer Guide

See [Developer Documentation](docs/developers/README.md) for comprehensive guidelines on:

- Codebase structure and architecture
- Development workflow and best practices
- Internal APIs and extension points
- Debugging tips and performance optimization
- Rustdoc generation and documentation standards

### Naming Conventions

```rust
// Types: PascalCase
struct AuthCache { }
enum Decision { }

// Functions and variables: snake_case
fn check_permission() { }
let user_id = "user:alice";

// Constants: SCREAMING_SNAKE_CASE
const MAX_DEPTH: usize = 10;

// Type parameters: Single uppercase letter or PascalCase
fn generic<T>() { }
fn generic<Store: TupleStore>() { }
```

### Documentation

Document public APIs with doc comments:

````rust
/// Checks if a subject has permission on a resource.
///
/// # Arguments
///
/// * `request` - The authorization check request
///
/// # Returns
///
/// Returns `Decision::Allow` if the check passes, `Decision::Deny` otherwise.
///
/// # Errors
///
/// Returns an error if the evaluation fails due to store errors or
/// invalid schema definitions.
///
/// # Example
///
/// ```
/// let decision = evaluator.check(CheckRequest {
///     subject: "user:alice".to_string(),
///     resource: "document:readme".to_string(),
///     permission: "can_view".to_string(),
///     context: None,
/// }).await?;
/// ```
pub async fn check(&self, request: CheckRequest) -> Result<Decision> {
    // ...
}
````

### Error Handling

- Use `Result` for fallible operations
- Use custom error types with `thiserror`
- Provide context in error messages

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("Store error: {0}")]
    Store(#[from] StoreError),

    #[error("Circular dependency detected at depth {depth}")]
    CircularDependency { depth: usize },
}
```

### Async Code

- Use `async/await` for asynchronous operations
- Prefer `tokio` for async runtime
- Document if a function blocks or is CPU-intensive

```rust
/// Evaluates a check request asynchronously.
///
/// This function is async and will not block the current thread.
pub async fn check(&self, request: CheckRequest) -> Result<Decision> {
    // Async implementation
}
```

## Testing Guidelines

### Unit Tests

Write unit tests for individual functions:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_validation() {
        let token = RevisionToken::new("node1".to_string(), 42);
        assert!(token.validate().is_ok());
    }

    #[tokio::test]
    async fn test_async_operation() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

### Integration Tests

Place integration tests in `tests/` directory:

```rust
// tests/integration_test.rs
use inferadb::*;

#[tokio::test]
async fn test_end_to_end() {
    // Test complete workflow
}
```

### Test Coverage

- Aim for >80% code coverage
- Test happy paths and error cases
- Include edge cases and boundary conditions

### Benchmarks

Add benchmarks for performance-critical code:

```rust
// benches/my_benchmark.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_function(c: &mut Criterion) {
    c.bench_function("my_function", |b| {
        b.iter(|| {
            my_function(black_box(input))
        })
    });
}

criterion_group!(benches, benchmark_function);
criterion_main!(benches);
```

## Documentation Guidelines

### Code Documentation

- Document all public APIs
- Include examples in doc comments
- Explain non-obvious behavior
- Document invariants and assumptions

### User Documentation

- Place user-facing docs in `docs/`
- Use Markdown format
- Include code examples
- Keep docs up to date with code changes

### API Documentation

- Update API docs when changing endpoints
- Include request/response examples
- Document error codes and meanings

## Review Process

### What Reviewers Look For

1. **Correctness** - Does the code work as intended?
2. **Tests** - Are there adequate tests?
3. **Style** - Does it follow our guidelines?
4. **Documentation** - Is it well documented?
5. **Performance** - Are there performance implications?
6. **Security** - Are there security concerns?

### Responding to Feedback

- Be open to suggestions
- Ask questions if feedback is unclear
- Make requested changes promptly
- Explain your reasoning when disagreeing

## Release Process

Maintainers handle releases:

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Tag the release
4. Publish to crates.io (if applicable)
5. Create GitHub release

## Project Structure

```text
server/
├── crates/              # Workspace crates
│   ├── inferadb-api/      # REST and gRPC APIs
│   ├── inferadb-bin/      # Main binary
│   ├── inferadb-cache/    # Caching layer
│   ├── inferadb-config/   # Configuration
│   ├── inferadb-core/     # Evaluation engine
│   ├── inferadb-observe/  # Observability
│   ├── inferadb-repl/     # Replication
│   ├── inferadb-store/    # Storage backends
│   └── inferadb-wasm/     # WASM integration
├── docs/                # Documentation
├── tests/               # Integration tests
├── benches/             # Benchmarks
├── Cargo.toml          # Workspace definition
└── CONTRIBUTING.md     # This file
```

## Getting Help

- **Documentation**: See `docs/` directory
- **Issues**: <https://github.com/inferadb/server/issues>
- **Discussions**: <https://github.com/inferadb/server/discussions>
- **Discord**: Join our community server (link TBD)

## Feature Requests

When proposing new features:

1. **Check existing issues** - Has it been proposed before?
2. **Open a discussion** - Discuss the feature with maintainers
3. **Write a proposal** - Describe the feature, use cases, and design
4. **Wait for feedback** - Get input before implementing
5. **Submit a PR** - Implement the feature once approved

## Bug Reports

When reporting bugs:

1. **Search existing issues** - Has it been reported?
2. **Provide details**:
   - InferaDB version
   - Rust version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Logs or error messages
3. **Minimal reproduction** - Provide a minimal example if possible

### Bug Report Template

````markdown
**InferaDB Version**: 0.1.0
**Rust Version**: 1.85.0
**OS**: Ubuntu 22.04

**Description**:
Brief description of the bug.

**Steps to Reproduce**:

1. Step one
2. Step two
3. Step three

**Expected Behavior**:
What should happen.

**Actual Behavior**:
What actually happens.

**Logs/Errors**:

```text
Error messages or logs here
```

**Additional Context**:
Any other relevant information.
````

## Performance Improvements

When optimizing performance:

1. **Benchmark first** - Measure before and after
2. **Profile** - Use profiling tools to find bottlenecks
3. **Document trade-offs** - Explain complexity vs. performance
4. **Maintain correctness** - Don't sacrifice correctness for speed

## Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:

1. Email <security@inferadb.io> (or maintainer email)
2. Include detailed description
3. Wait for response before disclosure
4. Allow time for fix before public disclosure

## License

By contributing to InferaDB, you agree that your contributions will be licensed under the [Business Source License 1.1](LICENSE).

### Developer Certificate of Origin

By making a contribution, you certify that you have the right to submit it under the project license. Your commits signify agreement to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/).

## Recognition

Contributors will be:

- Listed in `CONTRIBUTORS.md`
- Credited in release notes
- Mentioned in documentation (where appropriate)

## Questions?

Don't hesitate to ask questions:

- Open a discussion on GitHub
- Ask in pull request comments
- Join our Discord community

Thank you for contributing to InferaDB!
