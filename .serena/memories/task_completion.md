# InferaDB - Task Completion Checklist

When completing a task, run these commands to verify quality:

## Minimum Required Checks
```bash
make check
```
This runs:
1. `make format` - Format code with `cargo +nightly fmt --all`
2. `make lint` - Run `cargo clippy --workspace --all-targets -- -D warnings`
3. `make audit` - Run `cargo audit` for security vulnerabilities

## For Code Changes
```bash
make test                     # Run unit tests
make test-integration         # Run integration tests (if applicable)
```

## Full CI Simulation (Before Push)
```bash
make ci
```
This runs: `check`, `test`, and `deny` in sequence.

## Additional Checks (As Needed)
- `make test-fdb` - If changes affect FoundationDB storage
- `make coverage` - If adding new code paths
- `make bench` - If performance-sensitive changes
- `make deny` - Check for dependency issues

## Documentation Updates
- Update relevant docs in `docs/` if behavior changes
- Update doc comments for API changes
- Run `make doc` to verify documentation builds

## Commit Guidelines
- Run `make check` before committing
- Use conventional commit format: `type: subject`
- Keep commits focused and atomic
