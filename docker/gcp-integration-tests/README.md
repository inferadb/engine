# GCP Secret Manager Integration Tests - Docker Environment

This directory contains a **dedicated Docker environment** for running GCP Secret Manager unit tests.

**Note:** Google Cloud does not provide an official Secret Manager emulator. This environment runs unit tests that don't require real GCP credentials. Integration tests that require real GCP access are marked with `#[ignore]` and must be run separately with proper credentials.

## Overview

This setup provides:

- **Test runner** with Rust environment
- **Automated unit test execution** for GCP Secret Manager code
- **Complete isolation** for testing code paths
- **Zero GCP credentials** required for unit tests

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- At least 2GB of available RAM
- At least 3GB of disk space

### Run Tests

```bash
# From the server directory
./docker/gcp-integration-tests/test.sh
```

This will:

1. Build the test environment
2. Run GCP Secret Manager unit tests
3. Clean up automatically

**For full integration tests with real GCP:**

```bash
# 1. Set up Application Default Credentials
gcloud auth application-default login

# 2. Set your GCP project ID
export GCP_PROJECT_ID=your-project-id

# 3. Create a test secret in your GCP project
gcloud secrets create test-secret --data-file=- <<< "test-value"

# 4. Run integration tests
cargo test --package infera-config --features gcp-secrets test_gcp_secrets_provider -- --ignored --nocapture
```

## Usage

### Basic Commands

```bash
# Run tests (builds, runs, and cleans up)
./docker/gcp-integration-tests/test.sh

# Get a shell in the test container for debugging
./docker/gcp-integration-tests/shell.sh

# Clean up all test resources
./docker/gcp-integration-tests/cleanup.sh
```

### Advanced Usage

#### Keep Environment Running After Tests

Useful for debugging test failures:

```bash
# Start environment manually
cd docker/gcp-integration-tests
docker-compose up -d

# Run tests manually
docker-compose exec test-runner /workspace/docker/gcp-integration-tests/run-tests.sh

# Access container for debugging
./shell.sh

# When done
docker-compose down
```

#### Manual Test Execution

```bash
# Start environment
cd docker/gcp-integration-tests
docker-compose up -d

# Access container
docker-compose exec test-runner bash

# Inside container - run specific tests
cargo test -p infera-config --features gcp-secrets --lib gcp

# Check emulator secrets
gcloud secrets list --project=test-project

# View a specific secret
gcloud secrets versions access latest --secret=test-secret-1 --project=test-project

# Exit and cleanup
exit
docker-compose down
```

## Architecture

### Components

1. **Test Runner Container** (`test-runner`)
   - Based on `rust:1-slim` with nightly toolchain
   - All Rust dependencies cached
   - Source code mounted for live development
   - Runs unit tests that don't require real GCP

2. **Shared Network** (`gcp-test-network`)
   - Isolated bridge network for test isolation

3. **Volumes**
   - `cargo-registry`: Cached cargo dependencies
   - `cargo-git`: Cached git dependencies
   - `target-cache`: Compiled artifacts cache

### Architecture

```text
┌─────────────────────────────────────┐
│  Docker Network: gcp-test-network   │
│                                      │
│  ┌─────────────────────────────┐    │
│  │  test-runner                │    │
│  │  (Rust Unit Tests)          │    │
│  │                              │    │
│  │  - Mounts: source code       │    │
│  │  - Cache: volumes            │    │
│  │  - Tests GCP provider code   │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

**Note:** Since GCP doesn't provide a Secret Manager emulator, this environment focuses on unit testing the GCP Secret Manager provider code. Integration tests requiring real GCP credentials must be run separately.

## Files

- **`Dockerfile`** - Test runner container definition
- **`docker-compose.yml`** - Multi-container orchestration
- **`run-tests.sh`** - Main test execution script
- **`test.sh`** - Convenience wrapper for running tests
- **`shell.sh`** - Get interactive shell in test container
- **`cleanup.sh`** - Remove all test resources
- **`README.md`** - This file

## Environment Variables

### Test Runner

- `GCP_PROJECT_ID`: Project ID for integration tests (default: `test-project`)
- `RUST_BACKTRACE`: Enable Rust backtraces (default: `1`)
- `RUST_LOG`: Logging level (default: `debug`)

**For integration tests with real GCP:**

- `GOOGLE_APPLICATION_CREDENTIALS`: Path to service account JSON key file
- Or use Application Default Credentials via `gcloud auth application-default login`

## Troubleshooting

### Tests Fail with Connection Error

**Symptom:** Tests report "Failed to connect to GCP" or timeout errors.

**Solutions:**

1. Check emulator is healthy: `docker-compose ps`
2. View emulator logs: `docker-compose logs fake-gcp`
3. Check emulator health: `curl http://localhost:8085`
4. Verify secrets exist:

   ```bash
   docker-compose exec test-runner gcloud secrets list --project=test-project
   ```

### Build Fails with "No Space Left on Device"

**Solution:** Clean up Docker resources

```bash
./docker/gcp-integration-tests/cleanup.sh
docker system prune -a
```

### Tests Run Slowly

**Solution:** Increase Docker resource limits

- Docker Desktop → Settings → Resources
- Increase CPUs to 2+
- Increase Memory to 4GB+

### Emulator Container Keeps Restarting

**Solution:** Check health check logs

```bash
docker-compose logs fake-gcp
docker inspect inferadb-gcp-test
```

The health check waits up to 50 seconds for the emulator to initialize. If it's consistently failing:

1. Ensure you have sufficient resources
2. Check Docker daemon logs
3. Try pulling the latest image: `docker pull ghcr.io/googlecloudplatform/cloud-sdk-docker:emulators`

## GCP Emulator Features

The official GCP Secret Manager emulator provides:

- **Full API compatibility** with GCP Secret Manager API
- **Secret creation, retrieval, update, deletion**
- **Secret versioning**
- **IAM permissions** (simplified)
- **Labels and annotations**

### Limitations

The emulator has some limitations compared to real GCP:

- No encryption at rest (data is ephemeral)
- Simplified IAM model
- No audit logging
- Some advanced features may not be supported
- Performance characteristics differ from real GCP

## Development Workflow

### Adding New Tests

1. Write tests in `crates/infera-config/src/secrets.rs`
2. Ensure tests use `SECRETMANAGER_EMULATOR_HOST` environment variable
3. Run tests: `./docker/gcp-integration-tests/test.sh`
4. Iterate in interactive mode:

   ```bash
   ./docker/gcp-integration-tests/shell.sh
   # Inside container
   cargo test -p infera-config --features gcp-secrets <test_name>
   ```

### Debugging Test Failures

1. Start environment:

   ```bash
   cd docker/gcp-integration-tests
   docker-compose up -d
   ```

2. Access container:

   ```bash
   ./shell.sh
   ```

3. Inspect emulator state:

   ```bash
   # List all secrets
   gcloud secrets list --project=test-project

   # Get secret value
   gcloud secrets versions access latest \
     --secret=test-secret-1 \
     --project=test-project

   # Describe secret
   gcloud secrets describe test-secret-1 --project=test-project
   ```

4. Re-run specific test:

   ```bash
   RUST_BACKTRACE=full cargo test -p infera-config \
     --features gcp-secrets \
     test_name -- --nocapture
   ```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: GCP Integration Tests

on: [push, pull_request]

jobs:
  gcp-tests:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Run GCP Integration Tests
        run: |
          cd server
          ./docker/gcp-integration-tests/test.sh
```

### GitLab CI Example

```yaml
gcp-integration-tests:
  image: docker:latest
  services:
    - docker:dind
  script:
    - cd server
    - ./docker/gcp-integration-tests/test.sh
```

## Performance Considerations

### Resource Usage

- **Emulator Container:** ~300MB RAM, 1 CPU under normal load
- **Test Runner:** ~2GB RAM during compilation, ~300MB during tests
- **Volumes:** ~1-2GB for cached dependencies and builds

### Optimization Tips

1. **Reuse volumes** between test runs (automatic with docker-compose)
2. **Pre-build images** in CI
3. **Use cache mounts** (already configured)
4. **Run tests in parallel** where possible

## Security Notes

⚠️ **For Testing Only - Not for Production**

- Emulator uses fake credentials
- No encryption or authentication
- Data is ephemeral (cleared on container restart)
- No IAM or fine-grained permissions

**Do not:**

- Use real GCP credentials in this environment
- Store sensitive data in the emulator
- Connect production services to the emulator
- Rely on this for production testing

## Comparison with Real GCP

| Feature           | GCP Emulator     | Real GCP Secret Manager  |
| ----------------- | ---------------- | ------------------------ |
| Cost              | Free             | Pay per secret/operation |
| Speed             | Fast (local)     | Network latency          |
| Encryption        | Simulated        | Real KMS encryption      |
| IAM               | Simplified       | Full IAM integration     |
| Audit Logs        | None             | Cloud Audit Logs         |
| Secret Rotation   | Basic            | Full integration         |
| High Availability | Single container | Multi-region             |
| Data Persistence  | Ephemeral        | Durable storage          |

## Support

For issues specific to:

- **This Docker setup:** Check this README and troubleshooting section
- **GCP Emulator:** <https://cloud.google.com/sdk/gcloud/reference/beta/emulators/secretmanager>
- **GCP Secret Manager:** See GCP documentation
- **InferaDB:** See main project documentation

## License

This test environment follows the same license as the main InferaDB project.
