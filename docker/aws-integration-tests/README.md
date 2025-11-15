# AWS Secrets Manager Integration Tests - Docker Environment

This directory contains a **dedicated Docker environment** for running AWS Secrets Manager integration tests using LocalStack.

## Overview

This setup provides:

- **LocalStack** - AWS service emulation (Secrets Manager)
- **Test runner** with Rust environment and AWS CLI
- **Automated test execution** with proper LocalStack initialization
- **Complete isolation** from real AWS services
- **Zero AWS credentials** required

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- At least 2GB of available RAM
- At least 3GB of disk space

### Run Tests

```bash
# From the server directory
./docker/aws-integration-tests/test.sh
```

This will:

1. Build the test environment
2. Start LocalStack (AWS emulation)
3. Wait for LocalStack to be ready
4. Create test secrets in LocalStack
5. Run all AWS Secrets Manager integration tests
6. Clean up automatically

## Usage

### Basic Commands

```bash
# Run tests (builds, runs, and cleans up)
./docker/aws-integration-tests/test.sh

# Get a shell in the test container for debugging
./docker/aws-integration-tests/shell.sh

# Clean up all test resources
./docker/aws-integration-tests/cleanup.sh
```

### Advanced Usage

#### Keep Environment Running After Tests

Useful for debugging test failures:

```bash
# Start environment manually
cd docker/aws-integration-tests
docker-compose up -d

# Run tests manually
docker-compose exec test-runner /workspace/docker/aws-integration-tests/run-tests.sh

# Access container for debugging
./shell.sh

# When done
docker-compose down
```

#### Manual Test Execution

```bash
# Start environment
cd docker/aws-integration-tests
docker-compose up -d

# Access container
docker-compose exec test-runner bash

# Inside container - run specific tests
cargo test -p infera-config --features aws-secrets --lib aws

# Check LocalStack secrets
aws --endpoint-url=http://localstack:4566 secretsmanager list-secrets

# View a specific secret
aws --endpoint-url=http://localstack:4566 secretsmanager get-secret-value --secret-id test-secret-1

# Exit and cleanup
exit
docker-compose down
```

## Architecture

### Components

1. **LocalStack Container** (`localstack`)
   - Image: `localstack/localstack:latest`
   - Provides AWS Secrets Manager emulation
   - Accessible at `http://localstack:4566`
   - Health checks ensure service is ready before tests run

2. **Test Runner Container** (`test-runner`)
   - Based on `rust:1-slim` with nightly toolchain
   - AWS CLI installed for test setup
   - All Rust dependencies cached
   - Source code mounted for live development

3. **Shared Network** (`aws-test-network`)
   - Isolated bridge network
   - Allows containers to communicate
   - Port 4566 exposed for LocalStack gateway

4. **Volumes**
   - `localstack-data`: LocalStack state
   - `cargo-registry`: Cached cargo dependencies
   - `cargo-git`: Cached git dependencies
   - `target-cache`: Compiled artifacts cache

### Network Topology

```
┌─────────────────────────────────────────────┐
│  Docker Network: aws-test-network           │
│                                              │
│  ┌──────────────────┐  ┌─────────────────┐  │
│  │  localstack      │  │  test-runner    │  │
│  │  (AWS Services)  │◄─┤  (Rust + Tests) │  │
│  │                  │  │                 │  │
│  │  Port: 4566      │  │  Mounts: source │  │
│  │  Health: checked │  │  Cache: volumes │  │
│  └──────────────────┘  └─────────────────┘  │
│           │                                  │
│           │ (shared volumes)                 │
│           ▼                                  │
│    localstack-data volume                    │
└─────────────────────────────────────────────┘
```

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

- `AWS_ACCESS_KEY_ID`: Set to `test` (LocalStack doesn't validate)
- `AWS_SECRET_ACCESS_KEY`: Set to `test` (LocalStack doesn't validate)
- `AWS_DEFAULT_REGION`: Default AWS region (default: `us-east-1`)
- `AWS_ENDPOINT_URL`: LocalStack endpoint (default: `http://localstack:4566`)
- `RUST_BACKTRACE`: Enable Rust backtraces (default: `1`)
- `RUST_LOG`: Logging level (default: `debug`)

## Troubleshooting

### Tests Fail with Connection Error

**Symptom:** Tests report "Failed to connect to AWS" or timeout errors.

**Solutions:**

1. Check LocalStack is healthy: `docker-compose ps`
2. View LocalStack logs: `docker-compose logs localstack`
3. Check LocalStack health: `curl http://localhost:4566/_localstack/health`
4. Verify secrets exist:
   ```bash
   docker-compose exec test-runner aws --endpoint-url=http://localstack:4566 secretsmanager list-secrets
   ```

### Build Fails with "No Space Left on Device"

**Solution:** Clean up Docker resources

```bash
./docker/aws-integration-tests/cleanup.sh
docker system prune -a
```

### Tests Run Slowly

**Solution:** Increase Docker resource limits

- Docker Desktop → Settings → Resources
- Increase CPUs to 2+
- Increase Memory to 4GB+

### LocalStack Container Keeps Restarting

**Solution:** Check health check logs

```bash
docker-compose logs localstack
docker inspect inferadb-aws-test
```

The health check waits up to 50 seconds for LocalStack to initialize. If it's consistently failing:

1. Ensure you have sufficient resources
2. Check Docker daemon logs
3. Try pulling the latest LocalStack image: `docker pull localstack/localstack:latest`

## LocalStack Features

LocalStack provides emulation for AWS Secrets Manager with:

- **Full API compatibility** with AWS SDK
- **Secret creation, retrieval, update, deletion**
- **Secret versioning**
- **Secret rotation** (basic support)
- **Tags and metadata**

### Limitations

LocalStack is an emulator and has some limitations compared to real AWS:

- No real encryption at rest
- Simpler IAM/permissions model
- Some advanced features may not be fully supported
- Performance characteristics differ from real AWS

## Development Workflow

### Adding New Tests

1. Write tests in `crates/infera-config/src/secrets/aws.rs`
2. Ensure tests use `AWS_ENDPOINT_URL` environment variable
3. Run tests: `./docker/aws-integration-tests/test.sh`
4. Iterate in interactive mode:
   ```bash
   ./docker/aws-integration-tests/shell.sh
   # Inside container
   cargo test -p infera-config --features aws-secrets <test_name>
   ```

### Debugging Test Failures

1. Start environment:
   ```bash
   cd docker/aws-integration-tests
   docker-compose up -d
   ```

2. Access container:
   ```bash
   ./shell.sh
   ```

3. Inspect LocalStack state:
   ```bash
   # List all secrets
   aws --endpoint-url=http://localstack:4566 secretsmanager list-secrets

   # Get secret value
   aws --endpoint-url=http://localstack:4566 secretsmanager get-secret-value \
     --secret-id test-secret-1

   # Describe secret
   aws --endpoint-url=http://localstack:4566 secretsmanager describe-secret \
     --secret-id test-secret-1
   ```

4. Re-run specific test:
   ```bash
   RUST_BACKTRACE=full cargo test -p infera-config \
     --features aws-secrets \
     test_name -- --nocapture
   ```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: AWS Integration Tests

on: [push, pull_request]

jobs:
  aws-tests:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Run AWS Integration Tests
        run: |
          cd server
          ./docker/aws-integration-tests/test.sh
```

### GitLab CI Example

```yaml
aws-integration-tests:
  image: docker:latest
  services:
    - docker:dind
  script:
    - cd server
    - ./docker/aws-integration-tests/test.sh
```

## Performance Considerations

### Resource Usage

- **LocalStack Container:** ~200MB RAM, 1 CPU under normal load
- **Test Runner:** ~2GB RAM during compilation, ~300MB during tests
- **Volumes:** ~1-2GB for cached dependencies and builds

### Optimization Tips

1. **Reuse volumes** between test runs (automatic with docker-compose)
2. **Pre-build images** in CI
3. **Use cache mounts** (already configured)
4. **Run tests in parallel** where possible

## Security Notes

⚠️ **For Testing Only - Not for Production**

- LocalStack credentials are hardcoded (`test`/`test`)
- No encryption or authentication
- Data is ephemeral (cleared on container restart)
- No IAM or fine-grained permissions

**Do not:**

- Use real AWS credentials in this environment
- Store sensitive data in LocalStack
- Connect production services to LocalStack
- Rely on this for production testing

## Comparison with Real AWS

| Feature             | LocalStack          | Real AWS Secrets Manager |
| ------------------- | ------------------- | ------------------------ |
| Cost                | Free                | Pay per secret/API call  |
| Speed               | Fast (local)        | Network latency          |
| Encryption          | Simulated           | Real KMS encryption      |
| IAM                 | Basic               | Full IAM integration     |
| Audit Logs          | Limited             | CloudTrail integration   |
| Secret Rotation     | Basic               | Full Lambda integration  |
| High Availability   | Single container    | Multi-AZ                 |
| Data Persistence    | Ephemeral           | Durable storage          |

## Support

For issues specific to:

- **This Docker setup:** Check this README and troubleshooting section
- **LocalStack:** https://docs.localstack.cloud/
- **AWS Secrets Manager:** See AWS documentation
- **InferaDB:** See main project documentation

## License

This test environment follows the same license as the main InferaDB project.
