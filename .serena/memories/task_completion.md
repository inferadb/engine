# InferaDB - Task Completion Checklist

When completing a task, run these commands to verify quality:

## Minimum Required Checks
```bash
cargo +nightly fmt --all                                # Format code
cargo clippy --workspace --all-targets -- -D warnings   # Lint
cargo audit                                             # Security audit
```

## For Code Changes
```bash
cargo nextest run --lib --workspace          # Run unit tests
cargo nextest run --test '*' --workspace     # Run integration tests (if applicable)
```

## Full CI Simulation (Before Push)
```bash
cargo +nightly fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --lib --workspace
cargo audit
cargo deny check
```

## Additional Checks (As Needed)
- `./docker/fdb-integration-tests/test.sh` - If changes affect FoundationDB storage
- `cargo llvm-cov --workspace --html` - If adding new code paths
- `cargo bench` - If performance-sensitive changes
- `cargo deny check` - Check for dependency issues

## Documentation Updates
- Update relevant docs in `docs/` if behavior changes
- Update doc comments for API changes
- Run `cargo doc --workspace --no-deps` to verify documentation builds

## Commit Guidelines
- Run format and lint before committing
- Use conventional commit format: `type: subject`
- Keep commits focused and atomic
