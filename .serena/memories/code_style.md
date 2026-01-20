# InferaDB Code Style & Conventions

## Rust Version & Toolchain
- Channel: `stable`
- Edition: 2021
- MSRV: 1.92
- Components: clippy, rust-analyzer, rust-src, rustfmt

## Formatting (rustfmt)
Configuration in `.rustfmt.toml`:
- `comment_width = 100`
- `group_imports = "StdExternalCrate"` (std, then external, then crate)
- `imports_granularity = "Crate"` (merge imports by crate)
- `style_edition = "2024"`
- `use_small_heuristics = "MAX"` (aggressive compaction)
- `wrap_comments = true`
- `newline_style = "Unix"`

**Important**: Use `cargo +nightly fmt` for formatting (required for style_edition 2024).

## Naming Conventions
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

## Error Handling
- Use `Result` for fallible operations
- Use `thiserror` for custom error types with `#[derive(Debug, Error)]`
- Use `anyhow` for application-level error propagation
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

## Async Code
- Use `async/await` for asynchronous operations
- Use `tokio` runtime
- Mark blocking/CPU-intensive functions with doc comments
- Use `async-trait` for async trait methods

## Documentation
- Document all public APIs with `///` doc comments
- Include `# Arguments`, `# Returns`, `# Errors`, `# Example` sections
- Use `#[doc(hidden)]` for internal implementation details

## Testing
- Unit tests in `#[cfg(test)] mod tests` within each file
- Integration tests in `tests/` directory
- Use `#[tokio::test]` for async tests
- Use `proptest` for property-based testing
- Aim for >80% code coverage

## Linting
- All code must pass `cargo clippy --workspace --all-targets -- -D warnings`
- No warnings allowed

## Commit Messages
Format: `type: subject`
Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`
