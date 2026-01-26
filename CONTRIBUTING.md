# Contributing to InferaDB

Thank you for your interest in contributing to [InferaDB](https://inferadb.com)! We welcome contributions from the community and are grateful for any help you can provide.

## Code of Conduct

This project and everyone participating in it is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [open@inferadb.com](mailto:open@inferadb.com).

## How to Contribute

### Reporting Issues

- **Bug Reports**: Search existing issues first to avoid duplicates. Include version information, steps to reproduce, expected vs actual behavior, and relevant logs.
- **Feature Requests**: Describe the use case, proposed solution, and alternatives considered.
- **Security Issues**: Do **not** open public issues for security vulnerabilities. Instead, email [security@inferadb.com](mailto:security@inferadb.com).

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the development workflow** documented in the repository's [README.md](README.md)
3. **Write clear commit messages** following [Conventional Commits](https://www.conventionalcommits.org/)
4. **Ensure all tests pass** before submitting
5. **Update documentation** if your changes affect public APIs or user-facing behavior
6. **Submit a pull request** with a clear description of your changes

### Running Tests

InferaDB uses [nextest](https://nexte.st) for test execution with multiple profiles for different scenarios:

| Profile | Command | Use Case |
|---------|---------|----------|
| `fast` | `cargo nextest run --profile fast` | Quick local validation, PR checks |
| `ci` | `cargo nextest run --profile ci` | Standard CI runs, push to main |
| `full` | `cargo nextest run --profile full` | Comprehensive testing including ignored tests |

**Profile characteristics:**

- **fast**: Fail-fast enabled, 30s timeout, minimal output. Best for rapid iteration.
- **ci**: Standard timeouts, retries enabled, JUnit output. Used in GitHub Actions.
- **full**: Runs all ignored tests (load, scale, stress), 5min timeout, 2 retries. For release validation.

**Environment variables:**

```bash
# Control proptest case count (default: 50)
PROPTEST_CASES=10 cargo nextest run --profile fast    # Minimal fuzzing
PROPTEST_CASES=500 cargo nextest run --profile full   # Comprehensive fuzzing
```

**Running specific test types:**

```bash
# Run only ignored load tests
cargo nextest run --profile full --run-ignored only

# Run a specific test package
cargo nextest run --profile ci -p inferadb-engine-core
```

### CI Test Behavior

The CI workflow automatically selects appropriate test depth based on the trigger event:

| Event | Profile | PROPTEST_CASES | Tests Run |
|-------|---------|----------------|-----------|
| Pull Request | `fast` | 10 | Smoke tests only (fuzz tests gated behind `test-full` feature) |
| Push to main | `ci` | 25 | Standard test suite with moderate fuzzing |
| Nightly (schedule) | `full` | 500 | Full suite including all ignored load/scale tests |
| Manual dispatch | `full` | 500 | Full suite on any branch via workflow_dispatch |

**Proptest regression caching**: CI caches proptest regression files (`**/proptest-regressions`) between runs. When a proptest failure is found, the regression file is saved so subsequent runs can reproduce the failure quickly without re-discovering it.

**Running full tests locally:**

```bash
# Equivalent to nightly CI
PROPTEST_CASES=500 cargo nextest run --profile full --features test-full --run-ignored all

# Or use the justfile target
just test-full
```

### Development Setup

Each repository has its own development setup and workflow. See the repository's [README.md](README.md) for prerequisites, build commands, and development workflow.

## Review Process

1. **Automated Checks**: CI will run tests, linters, and formatters
2. **Peer Review**: At least one maintainer will review your contribution
3. **Feedback**: Address any review comments
4. **Approval**: Once approved, a maintainer will merge your contribution

## License

By contributing to [InferaDB](https://github.com/inferadb), you agree that your contributions will be dual-licensed under:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

## Questions?

If you have questions or need help:

- Join our [Discord server](https://discord.gg/inferadb) to chat with the community
- Email us at [open@inferadb.com](mailto:open@inferadb.com)

Thank you for helping make InferaDB better!
