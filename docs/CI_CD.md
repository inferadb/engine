# CI/CD Pipeline

This document covers InferaDB's continuous integration and continuous deployment pipeline.

## Quick Reference

**5 Workflows:**
- `ci.yml` - Main CI (format, lint, build, test, coverage)
- `security.yml` - Security audits (daily + PR checks)
- `benchmark.yml` - Performance regression detection
- `release.yml` - Automated releases (binaries, Docker, SBOM, provenance)
- `dependency-review.yml` - Dependency vulnerability scanning

**Naming conventions:** See [.github/WORKFLOW_NAMING_GUIDE.md](../.github/WORKFLOW_NAMING_GUIDE.md)

---

## Running Tests Locally (Match CI Behavior)

Install required tools:

```bash
# Install cargo-nextest for faster parallel testing
cargo install cargo-nextest

# Install security audit tools
cargo install cargo-audit cargo-deny cargo-sbom

# Install coverage tool
cargo install cargo-tarpaulin
```

Run tests like CI:

```bash
# Run tests with nextest (30-50% faster)
cargo nextest run --workspace --profile ci

# Run doc tests
cargo test --workspace --doc

# Run security checks
cargo audit
cargo deny check

# Run benchmarks
cargo bench --workspace

# Generate coverage report
cargo tarpaulin --workspace --out html --output-dir coverage/
```

---

## Workflow Overview

### 1. ci.yml - Main CI Pipeline

Runs on all PRs and main branch pushes.

**Jobs:**
- **Rustfmt**: Format check with nightly toolchain
- **Clippy**: Linting with `-D warnings`
- **Build**: Multi-platform builds (Ubuntu, macOS) in debug and release modes
- **Test**: Tests with cargo-nextest + doc tests
- **Code Coverage**: tarpaulin with Codecov upload
- **Dependency Check**: cargo-outdated + duplicate detection
- **Documentation**: cargo doc build
- **CI Success**: Meta-job that validates all checks passed

**Optimizations:**
- sccache for 40-70% faster builds
- Swatinem/rust-cache for dependency caching
- Job parallelization
- Concurrency limits (cancels old PR runs)

**Expected runtime:** ~4-5 minutes (down from 8+ minutes)

### 2. security.yml - Security Audits

Runs daily at midnight UTC + on all PRs and main pushes.

**Jobs:**
- **Cargo Audit**: CVE detection via RustSec database
- **Cargo Deny**: License compliance and supply chain security
- **Security Tests**: IPL parser fuzzing, WASM sandbox security tests

**Features:**
- Posts findings to GitHub Security tab
- Blocks PRs with moderate+ vulnerabilities

### 3. benchmark.yml - Performance Testing

Runs on PRs and main branch pushes.

**Features:**
- Runs `cargo bench` across workspace
- Alerts if >25% slower than baseline
- Stores historical data in gh-pages branch
- Posts PR comments with performance delta
- Fails CI on significant regressions

**View results:** `https://<org>.github.io/inferadb/dev/bench/`

### 4. release.yml - Automated Releases

Triggered by version tags (`v*.*.*`) or manual dispatch.

**Build Matrix:**
- Linux x86_64 and ARM64
- macOS x86_64 and Apple Silicon (ARM64)

**Artifacts:**
- Stripped release binaries (compressed tar.gz)
- SBOM in SPDX 2.3 JSON format
- SLSA Level 3 provenance
- Docker images (Docker Hub + ghcr.io)

**Optional:**
- Publish to crates.io (if `CARGO_REGISTRY_TOKEN` configured)

### 5. dependency-review.yml - PR Dependency Checks

Runs only on pull requests.

**Features:**
- Blocks PRs with vulnerable dependencies (moderate+ severity)
- Enforces license compliance (denies GPL/AGPL/LGPL)
- Posts summary comment to PR
- Uses GitHub's native dependency graph

---

## Performance Optimizations

Our CI uses several optimizations for speed:

- **cargo-nextest**: 30-50% faster parallel testing with flaky test retry
- **sccache**: 40-70% faster incremental builds (caches compilation across runs)
- **Swatinem/rust-cache**: Optimized Rust dependency caching
- **Concurrency limits**: Cancels old PR runs when new commits pushed
- **Job parallelization**: Independent jobs run in parallel

**Expected CI time:** ~4-5 minutes (down from 8+ minutes without optimizations)

---

## Security Features

### Harden Runner

All workflows use **Step Security Harden Runner** (v2.13.1) for:

- Network egress monitoring and filtering
- Outbound traffic auditing
- Supply chain attack detection
- Insights dashboard at https://app.stepsecurity.io

### Supply Chain Security

- All GitHub Actions pinned to commit SHA (immutable)
- SBOM (Software Bill of Materials) for all releases
- SLSA Level 3 provenance for binary integrity
- Docker images include SBOM and provenance
- cargo-deny enforces license compliance

### Workflow Permissions

All workflows follow **least-privilege principle:**

- Default: `contents: read` (read-only)
- Job-level overrides only where needed
- No `write-all` permissions
- OIDC for Docker GitHub Container Registry

---

## Local Workflow Testing

Test workflows locally before pushing:

```bash
# Install act (https://github.com/nektos/act)
brew install act  # macOS
# or: curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run CI workflow locally
act pull_request -W .github/workflows/ci.yml

# Run specific job
act pull_request -W .github/workflows/ci.yml -j test

# Dry run (see what would run)
act pull_request -W .github/workflows/ci.yml --dryrun
```

---

## Troubleshooting CI

### Tests failing locally but passing in CI (or vice versa)

- Ensure you're using the same Rust version: `rustc --version`
- Run with same profile: `cargo nextest run --profile ci`
- Check test isolation (nextest runs tests in parallel)
- Verify environment variables match

### CI is slow

- First run in a PR is always slow (cold cache)
- Subsequent runs should be 40-70% faster (sccache hits)
- Avoid force-push or amend commits to preserve cache
- Check sccache stats in CI logs

### Dependency errors

- Update `Cargo.lock`: `cargo update`
- Check cargo-deny config in `deny.toml`
- Review security audit: `cargo audit`
- Check dependency-review PR comments

### Docker build fails

- Ensure Dockerfile is present
- Check `DOCKER_USERNAME` and `DOCKER_PASSWORD` secrets configured
- Verify Docker Hub account permissions
- Check ghcr.io token permissions

### Benchmark alerts

- PR comments show performance delta
- Investigate >25% slowdowns
- Profile hot paths with `cargo flamegraph`
- Check for unintended allocations

---

## Release Process

Releases are fully automated via tags.

### 1. Create and push a tag

```bash
# Create annotated tag
git tag -a v1.0.0 -m "Release v1.0.0"

# Push to trigger release workflow
git push origin v1.0.0
```

### 2. Release workflow automatically

- Builds binaries for 4 platforms (Linux + macOS, x86_64 + ARM64)
- Generates SBOM for each binary (SPDX 2.3 JSON)
- Creates SLSA Level 3 provenance
- Builds and pushes Docker images to Docker Hub + ghcr.io
- Publishes to crates.io (if token configured)

### 3. Verify release

```bash
# Download and inspect SBOM
gh release download v1.0.0 --pattern "sbom-*.spdx.json"
cat sbom-x86_64-unknown-linux-gnu.spdx.json | jq

# Verify SLSA provenance (requires slsa-verifier)
gh release download v1.0.0 --pattern "*.intoto.jsonl"
slsa-verifier verify-artifact inferadb-linux-x86_64.tar.gz \
  --provenance-path inferadb-linux-x86_64.tar.gz.intoto.jsonl \
  --source-uri github.com/inferadb/inferadb

# Pull and verify Docker image
docker pull inferadb/inferadb:v1.0.0
docker pull ghcr.io/inferadb/inferadb:v1.0.0

# Inspect SBOM/provenance in image
docker sbom inferadb/inferadb:v1.0.0
```

### Manual release (via workflow_dispatch)

```bash
# Trigger via GitHub CLI
gh workflow run release.yml -f version=v1.0.0

# Or via GitHub UI: Actions → Release → Run workflow
```

---

## Monitoring CI Performance

Track CI metrics over time:

```bash
# List recent CI runs with duration
gh run list --workflow=ci.yml --limit 10 --json conclusion,startedAt,updatedAt,durationMs \
  | jq '.[] | select(.conclusion=="success") | {duration: .durationMs}'

# View specific run logs
gh run view <run-id> --log

# Download artifacts from run
gh run download <run-id>

# Re-run failed jobs
gh run rerun <run-id> --failed
```

---

## Best Practices

### 1. Always run locally before pushing

```bash
cargo +nightly fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
```

### 2. Keep dependencies up to date

- Dependabot creates weekly PRs
- Review and merge promptly
- Check for breaking changes in CHANGELOG
- Run `cargo update` regularly

### 3. Monitor security advisories

- Daily cargo-audit runs
- Fix vulnerabilities ASAP
- cargo-deny blocks new vulnerable deps
- Review RustSec advisories: https://rustsec.org/advisories/

### 4. Review benchmark results

- Check PR comments for regressions
- Investigate >25% slowdowns
- Optimize hot paths before merging
- Use `cargo flamegraph` for profiling

### 5. Keep workflows secure

- Never use `pull_request_target` with secrets
- Always pin actions to commit SHA (not tags)
- Review Dependabot PRs for actions carefully
- Use OIDC tokens instead of long-lived secrets where possible

### 6. Manage cache effectively

- Use `shared-key` to share cache between jobs
- Clear cache if builds become stale: `gh cache delete <key>`
- Monitor cache size limits (10GB per repo)

---

## Related Documentation

- [Workflow Naming Guide](../.github/WORKFLOW_NAMING_GUIDE.md)
- [Security Policy](../SECURITY.md)
- [Benchmark Setup](../SETUP_GH_PAGES.md)
- [Cargo Deny Config](../deny.toml)
- [Nextest Config](../.config/nextest.toml)

---

Last updated: 2025-11-03
