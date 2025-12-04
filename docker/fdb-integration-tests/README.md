# FoundationDB Integration Tests - Docker Environment

This directory contains a **dedicated Docker environment** for running FoundationDB integration tests in complete isolation from production systems.

## Overview

This setup provides:

- **Isolated FDB cluster** running in a container
- **Test runner** with all required dependencies
- **Automated test execution** with proper FDB initialization
- **Cross-platform support** (works on ARM64 and x86_64)
- **Zero interference** with production environments

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- At least 4GB of available RAM
- At least 5GB of disk space

### Run Tests

```bash
# From the server directory
./docker/fdb-integration-tests/test.sh
```

This will:

1. Build the test environment
2. Start FoundationDB
3. Wait for FDB to be ready
4. Run all FDB integration tests
5. Clean up automatically

## Usage

### Basic Commands

```bash
# Run tests (builds, runs, and cleans up)
./docker/fdb-integration-tests/test.sh

# Get a shell in the test container for debugging
./docker/fdb-integration-tests/shell.sh

# Clean up all test resources (containers, volumes, networks)
./docker/fdb-integration-tests/cleanup.sh
```

### Advanced Usage

#### Keep Environment Running After Tests

Useful for debugging test failures:

```bash
KEEP_RUNNING=true ./docker/fdb-integration-tests/test.sh

# After tests complete, access the container
./docker/fdb-integration-tests/shell.sh

# When done
docker-compose -f docker/fdb-integration-tests/docker-compose.yml down
```

#### Run All Storage Tests (FDB + Memory)

```bash
# Start environment
cd docker/fdb-integration-tests
docker-compose up -d

# Run comprehensive tests
docker-compose exec test-runner bash -c "RUN_ALL_TESTS=true /workspace/docker/fdb-integration-tests/run-tests.sh"

# Cleanup
docker-compose down
```

#### Manual Test Execution

```bash
# Start environment
cd docker/fdb-integration-tests
docker-compose up -d

# Access container
docker-compose exec test-runner bash

# Inside container - run specific tests
cargo test -p infera-store --features fdb,fdb-integration-tests --lib foundationdb::tests::test_fdb_connection
cargo test -p infera-store --features fdb,fdb-integration-tests --lib foundationdb::tests::test_fdb_basic_operations

# Check FDB status
fdbcli --exec "status"

# View cluster file
cat $FDB_CLUSTER_FILE

# Exit and cleanup
exit
docker-compose down
```

## Architecture

### Components

1. **FoundationDB Container** (`foundationdb`)
   - Image: `foundationdb/foundationdb:7.3.69`
   - Single-node cluster for testing
   - Health checks ensure FDB is ready before tests run
   - Resource limits prevent runaway processes

2. **Test Runner Container** (`test-runner`)
   - Based on `rust:1.83-slim`
   - FDB client libraries installed
   - All Rust dependencies cached
   - Source code mounted for live development

3. **Shared Network** (`fdb-test-network`)
   - Isolated bridge network
   - Allows containers to communicate
   - No external access except port 4500 (optional)

4. **Volumes**
   - `fdb-config`: FDB cluster configuration (shared between containers)
   - `cargo-registry`: Cached cargo dependencies
   - `cargo-git`: Cached git dependencies
   - `target-cache`: Compiled artifacts cache

### Network Topology

```text
┌─────────────────────────────────────────────┐
│  Docker Network: fdb-test-network           │
│                                              │
│  ┌──────────────────┐  ┌─────────────────┐  │
│  │  foundationdb    │  │  test-runner    │  │
│  │  (FDB Server)    │◄─┤  (Rust + Tests) │  │
│  │                  │  │                 │  │
│  │  Port: 4500      │  │  Mounts: source │  │
│  │  Health: checked │  │  Cache: volumes │  │
│  └──────────────────┘  └─────────────────┘  │
│           │                                  │
│           │ (shared volume)                  │
│           ▼                                  │
│    fdb-config volume                         │
│    /var/fdb/fdb.cluster                      │
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

- `FDB_CLUSTER_FILE`: Path to FDB cluster file (default: `/etc/foundationdb/fdb.cluster`)
- `RUST_BACKTRACE`: Enable Rust backtraces (default: `1`)
- `RUST_LOG`: Logging level (default: `debug`)
- `RUN_ALL_TESTS`: Run all storage tests, not just FDB (default: `false`)

### Docker Compose

- `KEEP_RUNNING`: Don't auto-cleanup after tests (default: `false`)

## Troubleshooting

### Tests Fail with Connection Error

**Symptom:** Tests report "Failed to connect to FDB" or timeout errors.

**Solutions:**

1. Check FDB is healthy: `docker-compose ps`
2. View FDB logs: `docker-compose logs foundationdb`
3. Verify cluster file exists: `docker-compose exec test-runner cat $FDB_CLUSTER_FILE`
4. Check FDB status: `docker-compose exec foundationdb fdbcli --exec status`

### Build Fails with "No Space Left on Device"

**Solution:** Clean up Docker resources

```bash
./docker/fdb-integration-tests/cleanup.sh
docker system prune -a
```

### Tests Run Slowly

**Solution:** Increase Docker resource limits

- Docker Desktop → Settings → Resources
- Increase CPUs to 4+
- Increase Memory to 8GB+

### ARM64 (Apple Silicon) Issues

**Solution:** Docker automatically handles platform emulation. If you see warnings:

```bash
# Explicitly set platform for x86_64
DOCKER_DEFAULT_PLATFORM=linux/amd64 ./docker/fdb-integration-tests/test.sh
```

### Container Keeps Restarting

**Solution:** Check health check logs

```bash
docker-compose logs foundationdb
docker inspect inferadb-fdb-test
```

The health check waits up to 30 seconds for FDB to initialize. If it's consistently failing:

1. Ensure you have sufficient resources
2. Check Docker daemon logs
3. Try increasing `start_period` in `docker-compose.yml`

## CI/CD Integration

### GitHub Actions Example

```yaml
name: FDB Integration Tests

on: [push, pull_request]

jobs:
  fdb-tests:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Run FDB Integration Tests
        run: |
          cd server
          ./docker/fdb-integration-tests/test.sh
```

### GitLab CI Example

```yaml
fdb-integration-tests:
  image: docker:latest
  services:
    - docker:dind
  script:
    - cd server
    - ./docker/fdb-integration-tests/test.sh
```

## Performance Considerations

### Resource Usage

- **FDB Container:** ~500MB RAM, 1 CPU under normal load
- **Test Runner:** ~2GB RAM during compilation, ~500MB during tests
- **Volumes:** ~1-2GB for cached dependencies and builds

### Optimization Tips

1. **Reuse volumes** between test runs (automatic with docker-compose)
2. **Pre-build images** in CI:

   ```bash
   docker-compose build
   docker-compose push  # if using registry
   ```

3. **Use cache mounts** (already configured)
4. **Limit parallelism** for memory-constrained environments

## Security Notes

⚠️ **For Testing Only - Not Production Ready**

- No authentication configured
- No TLS/SSL encryption
- Single-node cluster (not resilient)
- Default FDB configuration (not hardened)
- Port 4500 exposed to host (optional, can be removed)

**Do not:**

- Use this configuration in production
- Store sensitive data in this environment
- Rely on this for data persistence
- Connect production services to this cluster

## Comparison with Production Setup

| Feature          | Test Environment  | Production               |
| ---------------- | ----------------- | ------------------------ |
| Cluster Size     | Single node       | Multi-node cluster       |
| Data Persistence | Ephemeral volumes | Persistent storage       |
| Authentication   | None              | Required                 |
| TLS/SSL          | None              | Required                 |
| Backup           | None              | Automated                |
| Monitoring       | Docker logs only  | Full observability stack |
| Resource Limits  | 2 CPU, 2GB RAM    | Scaled appropriately     |

## Development Workflow

### Adding New Tests

1. Write tests in `crates/infera-store/src/foundationdb.rs`
2. Mark with `#[cfg(all(test, feature = "fdb-integration-tests"))]`
3. Run tests: `./docker/fdb-integration-tests/test.sh`
4. Iterate in interactive mode:

   ```bash
   ./docker/fdb-integration-tests/shell.sh
   # Inside container
   cargo test -p infera-store --features fdb,fdb-integration-tests <test_name>
   ```

### Debugging Test Failures

1. Keep environment running:

   ```bash
   KEEP_RUNNING=true ./docker/fdb-integration-tests/test.sh
   ```

2. Access container:

   ```bash
   ./docker/fdb-integration-tests/shell.sh
   ```

3. Inspect FDB state:

   ```bash
   fdbcli
   > status
   > get \x01test_key
   > exit
   ```

4. Re-run specific test:

   ```bash
   RUST_BACKTRACE=full cargo test -p infera-store \
     --features fdb,fdb-integration-tests \
     test_name -- --nocapture
   ```

## Maintenance

### Updating FDB Version

1. Update version in `Dockerfile`:

   ```dockerfile
   RUN wget https://github.com/apple/foundationdb/releases/download/7.3.69/...
   ```

2. Update version in `docker-compose.yml`:

   ```yaml
   image: foundationdb/foundationdb:7.3.69
   ```

3. Rebuild:

   ```bash
   ./docker/fdb-integration-tests/cleanup.sh
   docker-compose build --no-cache
   ```

### Updating Rust Version

1. Update in `Dockerfile`:

   ```dockerfile
   FROM rust:1.83-slim
   ```

2. Rebuild:

   ```bash
   docker-compose build test-runner
   ```

## Support

For issues specific to:

- **This Docker setup:** Check this README and troubleshooting section
- **Storage layer:** See `docs/architecture.md`
- **InferaDB:** See main project documentation

## License

This test environment follows the same license as the main InferaDB project.
