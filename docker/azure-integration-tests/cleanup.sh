#!/bin/bash

echo "🧹 Cleaning up Azure integration test resources..."
echo ""

cd "$(dirname "$0")"

# Stop and remove containers
echo "Stopping containers..."
docker-compose down -v

# Remove volumes
echo "Removing volumes..."
docker volume rm inferadb-azure-cargo-registry 2>/dev/null || true
docker volume rm inferadb-azure-cargo-git 2>/dev/null || true
docker volume rm inferadb-azure-target-cache 2>/dev/null || true

# Remove network
echo "Removing network..."
docker network rm inferadb-azure-test-network 2>/dev/null || true

echo ""
echo "✅ Cleanup complete!"
