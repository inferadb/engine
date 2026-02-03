# Contributing to InferaDB

Thank you for your interest in contributing to [InferaDB](https://inferadb.com)!

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior to [open@inferadb.com](mailto:open@inferadb.com).

## Reporting Issues

- **Bugs**: Search existing issues first. Include version, steps to reproduce, and logs.
- **Features**: Describe the use case and proposed solution.
- **Security**: Email [security@inferadb.com](mailto:security@inferadb.com) (do not open public issues).

## Pull Requests

1. Fork and branch from `main`
2. Follow [Conventional Commits](https://www.conventionalcommits.org/)
3. Ensure tests pass: `just test`
4. Update documentation if needed
5. Submit PR with clear description

**PR title must follow Conventional Commits format** (validated by CI):
- `feat: add user authentication`
- `fix(api): handle empty requests`

## Development

```bash
mise trust && mise install     # Setup
just test                      # Run tests
just lint                      # Clippy
just fmt                       # Format
```

## Test Profiles

| Command | Use Case |
|---------|----------|
| `just test-fast` | Quick local validation |
| `just test` | Standard CI runs |
| `just test-full` | Comprehensive with load tests |

Control proptest iterations: `PROPTEST_CASES=500 just test-full`

## Review Process

1. Automated CI checks
2. Maintainer review
3. Address feedback
4. Merge on approval

## License

Contributions are dual-licensed under [Apache 2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).

## Questions?

- [Discord](https://discord.gg/inferadb)
- [open@inferadb.com](mailto:open@inferadb.com)
