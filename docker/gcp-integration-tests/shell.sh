#!/bin/bash

echo "🐚 Opening interactive shell in test-runner container..."
echo ""

cd "$(dirname "$0")"

# Check if containers are running
if ! docker-compose ps | grep -q "test-runner"; then
    echo "⚠️  Test environment is not running. Starting it now..."
    docker-compose up -d
    echo "⏳ Waiting for GCP emulator to be ready..."
    sleep 5
fi

# Get shell
docker-compose exec test-runner bash
