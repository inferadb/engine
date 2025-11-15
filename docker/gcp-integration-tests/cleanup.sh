#!/bin/bash

echo "🧹 Cleaning up GCP integration test environment..."

cd "$(dirname "$0")"

# Stop and remove containers
docker-compose down --volumes --remove-orphans 2>/dev/null || true

# Remove specific volumes
docker volume rm inferadb-gcp-cargo-registry 2>/dev/null || true
docker volume rm inferadb-gcp-cargo-git 2>/dev/null || true
docker volume rm inferadb-gcp-target-cache 2>/dev/null || true

# Remove network
docker network rm inferadb-gcp-test-network 2>/dev/null || true

# Remove containers by name
docker rm -f inferadb-gcp-test 2>/dev/null || true
docker rm -f inferadb-gcp-test-runner 2>/dev/null || true

echo "✅ Cleanup complete"
