#!/bin/bash
# Cleanup script for FDB integration test environment
# This removes all containers, volumes, and networks created by the test environment

set -e

cd "$(dirname "$0")"

echo "Cleaning up FDB Integration Test Environment..."
echo ""

# Stop and remove containers
echo "Stopping containers..."
docker-compose down -v

# Remove named volumes
echo "Removing volumes..."
docker volume rm -f inferadb-fdb-config 2>/dev/null || true
docker volume rm -f inferadb-cargo-registry 2>/dev/null || true
docker volume rm -f inferadb-cargo-git 2>/dev/null || true
docker volume rm -f inferadb-target-cache 2>/dev/null || true

# Remove network
echo "Removing network..."
docker network rm inferadb-fdb-test-net 2>/dev/null || true

# Remove any dangling test containers
echo "Removing dangling containers..."
docker ps -a | grep "inferadb.*test" | awk '{print $1}' | xargs -r docker rm -f 2>/dev/null || true

echo ""
echo "✓ Cleanup complete"
