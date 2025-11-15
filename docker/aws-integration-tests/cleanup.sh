#!/bin/bash

echo "🧹 Cleaning up AWS integration test environment..."

cd "$(dirname "$0")"

# Stop and remove containers
docker-compose down --volumes --remove-orphans 2>/dev/null || true

# Remove specific volumes
docker volume rm inferadb-aws-localstack-data 2>/dev/null || true
docker volume rm inferadb-aws-cargo-registry 2>/dev/null || true
docker volume rm inferadb-aws-cargo-git 2>/dev/null || true
docker volume rm inferadb-aws-target-cache 2>/dev/null || true

# Remove network
docker network rm inferadb-aws-test-network 2>/dev/null || true

# Remove containers by name
docker rm -f inferadb-aws-test 2>/dev/null || true
docker rm -f inferadb-aws-test-runner 2>/dev/null || true

echo "✅ Cleanup complete"
