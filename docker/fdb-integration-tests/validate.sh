#!/bin/bash
# Validate the FDB integration test setup without running tests
# This checks that all files are in place and configurations are valid

set -e

cd "$(dirname "$0")"

echo "=== Validating FDB Integration Test Setup ==="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

# Check required files exist
echo "Checking required files..."
FILES=(
    "Dockerfile"
    "docker-compose.yml"
    "run-tests.sh"
    "test.sh"
    "shell.sh"
    "cleanup.sh"
    "README.md"
    ".dockerignore"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "  ${GREEN}✓${NC} $file"
    else
        echo -e "  ${RED}✗${NC} $file - MISSING"
        ERRORS=$((ERRORS + 1))
    fi
done

echo ""

# Check scripts are executable
echo "Checking script permissions..."
SCRIPTS=(
    "run-tests.sh"
    "test.sh"
    "shell.sh"
    "cleanup.sh"
)

for script in "${SCRIPTS[@]}"; do
    if [ -x "$script" ]; then
        echo -e "  ${GREEN}✓${NC} $script is executable"
    else
        echo -e "  ${YELLOW}⚠${NC} $script is not executable"
        chmod +x "$script"
        echo -e "     Fixed: made $script executable"
    fi
done

echo ""

# Validate docker-compose.yml
echo "Validating docker-compose.yml..."
if docker-compose config --quiet 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} docker-compose.yml is valid"
else
    echo -e "  ${RED}✗${NC} docker-compose.yml has errors"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# Check Docker is running
echo "Checking Docker availability..."
if docker info >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Docker is running"
    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}')
    echo "     Version: $DOCKER_VERSION"
else
    echo -e "  ${RED}✗${NC} Docker is not running"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# Check Docker Compose is available
echo "Checking Docker Compose availability..."
if docker-compose version >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Docker Compose is available"
    COMPOSE_VERSION=$(docker-compose version --short)
    echo "     Version: $COMPOSE_VERSION"
else
    echo -e "  ${RED}✗${NC} Docker Compose is not available"
    ERRORS=$((ERRORS + 1))
fi

echo ""

# Check Dockerfile syntax
echo "Checking Dockerfile syntax..."
if docker build --help >/dev/null 2>&1; then
    # Simple validation - check for FROM command
    if grep -q "^FROM" Dockerfile; then
        echo -e "  ${GREEN}✓${NC} Dockerfile has valid FROM instruction"
    else
        echo -e "  ${RED}✗${NC} Dockerfile missing FROM instruction"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "  ${YELLOW}⚠${NC} Cannot validate Dockerfile (docker build not available)"
fi

echo ""

# Check source directory structure
echo "Checking InferaDB source structure..."
if [ -f "../../Cargo.toml" ]; then
    echo -e "  ${GREEN}✓${NC} Root Cargo.toml found"
else
    echo -e "  ${RED}✗${NC} Root Cargo.toml not found - wrong directory?"
    ERRORS=$((ERRORS + 1))
fi

if [ -d "../../crates/infera-store" ]; then
    echo -e "  ${GREEN}✓${NC} infera-store crate found"
else
    echo -e "  ${RED}✗${NC} infera-store crate not found"
    ERRORS=$((ERRORS + 1))
fi

if [ -f "../../crates/infera-store/src/foundationdb.rs" ]; then
    echo -e "  ${GREEN}✓${NC} FoundationDB implementation found"
else
    echo -e "  ${RED}✗${NC} FoundationDB implementation not found"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "=== Validation Complete ==="
echo ""

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Build and run tests: ./test.sh"
    echo "  2. Get a shell: ./shell.sh"
    echo "  3. Read documentation: cat README.md"
    exit 0
else
    echo -e "${RED}✗ Found $ERRORS error(s)${NC}"
    echo ""
    echo "Please fix the errors above before running tests."
    exit 1
fi
