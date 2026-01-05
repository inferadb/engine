# Makefile for the InferaDB Authorization Engine
# Provides convenient shortcuts for common cargo commands
#
# Quick start:
#   make setup    - One-time setup (installs tools)
#   make test     - Run all tests
#   make check    - Run all quality checks
#   make dev      - Start development server with watch
#
# Use 'make help' to see all available commands

.PHONY: help setup test test-integration test-leaks test-load test-fdb test-aws test-gcp test-azure check format lint audit deny run build release clean reset dev doc coverage bench expand outdated tree bloat fix docker-build docker-run k8s-deploy k8s-delete ci

# Use mise exec if available, otherwise use system cargo
CARGO := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- cargo" || echo "cargo")

# Default target - show help
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "InferaDB Development Commands"
	@echo ""
	@echo "Setup & Development:"
	@grep -E '^(setup|run|dev|build|release|clean|reset):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Testing:"
	@grep -E '^test.*:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Code Quality:"
	@grep -E '^(check|format|lint|audit|deny|fix):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Documentation & Analysis:"
	@grep -E '^(doc|coverage|bench|tree|bloat|outdated):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Docker & Kubernetes:"
	@grep -E '^(docker|k8s).*:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "CI/CD:"
	@grep -E '^ci:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Use 'cargo <command> --help' for more options"
	@echo ""

setup: ## One-time development environment setup
	@echo "🔧 Setting up development environment..."
	@if command -v mise > /dev/null 2>&1; then \
		mise trust && mise install; \
	else \
		echo "⚠️  mise not found - using system cargo"; \
	fi
	@$(CARGO) fetch
	@echo "✅ Setup complete!"

test: ## Run unit tests
	@echo "🧪 Running unit tests..."
	@$(CARGO) nextest run --lib --workspace

test-integration: ## Run integration tests
	@echo "🧪 Running integration tests..."
	@$(CARGO) nextest run --test '*' --workspace

test-leaks: ## Run memory leak detection tests
	@echo "🧪 Running memory leak detection tests..."
	@$(CARGO) test --test memory_leak_tests --package infera-api

test-load: ## Run load/stress tests (ignored by default)
	@echo "🧪 Running load/stress tests..."
	@$(CARGO) test --package infera-core --test performance_load -- --ignored --test-threads=1

test-fdb: ## Run FoundationDB integration tests (requires Docker)
	@echo "🧪 Running FDB integration tests..."
	@./docker/fdb-integration-tests/test.sh

test-aws: ## Run AWS Secrets Manager tests (requires Docker)
	@echo "🧪 Running AWS Secrets Manager tests..."
	@./docker/aws-integration-tests/test.sh

test-gcp: ## Run GCP Secret Manager tests (requires Docker)
	@echo "🧪 Running GCP Secret Manager tests..."
	@./docker/gcp-integration-tests/test.sh

test-azure: ## Run Azure Key Vault tests (requires Docker)
	@echo "🧪 Running Azure Key Vault tests..."
	@./docker/azure-integration-tests/test.sh

check: ## Run code quality checks (format, lint, audit)
	@echo "🔍 Running code quality checks..."
	@$(MAKE) format
	@$(MAKE) lint
	@$(MAKE) audit
	@echo "✅ All checks passed!"

format: ## Format code (rustfmt)
	@echo "📝 Formatting code..."
	@$(CARGO) +nightly fmt --all
	@echo "✅ Formatting complete!"

lint: ## Run linters (clippy)
	@echo "🔍 Running linters..."
	@$(CARGO) clippy --workspace --all-targets -- -D warnings

audit: ## Run security audit
	@echo "🔒 Running security audit..."
	@$(CARGO) audit

deny: ## Check dependencies with cargo-deny
	@echo "🔍 Checking dependencies..."
	@$(CARGO) deny check

run: ## Run the inferadb engine (debug mode)
	@echo "🚀 Starting InferaDB engine..."
	@$(CARGO) run --bin inferadb-engine

build: ## Build debug binary
	@echo "🔨 Building debug binary..."
	@$(CARGO) build

release: ## Build optimized release binary
	@echo "🚀 Building release binary..."
	@$(CARGO) build --release --workspace

clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	@$(CARGO) clean

reset: ## Reset the dev environment
	@echo "🧹 Stopping and removing Docker containers..."
	-@docker ps -aq | xargs -r docker stop 2>/dev/null || true
	-@docker ps -aq | xargs -r docker rm 2>/dev/null || true

	@echo "🧹 Removing Docker volumes..."
	-@docker volume ls -q | grep -E 'inferadb|fdb' | xargs -r docker volume rm 2>/dev/null || true

	@echo "🧹 Removing Docker networks..."
	-@docker network ls -q | grep -E 'inferadb|fdb' | xargs -r docker network rm 2>/dev/null || true

	@echo "🧹 Cleaning FDB test environment..."
	-@./docker/fdb-integration-tests/cleanup.sh 2>/dev/null || true

	@echo "🧹 Cleaning AWS test environment..."
	-@./docker/aws-integration-tests/cleanup.sh 2>/dev/null || true

	@echo "🧹 Cleaning GCP test environment..."
	-@./docker/gcp-integration-tests/cleanup.sh 2>/dev/null || true

	@echo "🧹 Cleaning Azure test environment..."
	-@./docker/azure-integration-tests/cleanup.sh 2>/dev/null || true

	@echo "🧹 Cleaning cargo build artifacts..."
	@$(CARGO) clean

	@echo "🧹 Clearing cargo registry cache..."
	-@rm -rf ~/.cargo/registry/cache/* 2>/dev/null || true
	-@rm -rf ~/.cargo/git/db/* 2>/dev/null || true

	@echo "🧹 Clearing target directory..."
	-@rm -rf target/ 2>/dev/null || true

	@echo "🧹 Clearing mise cache..."
	-@rm -rf ~/.local/share/mise/installs/* 2>/dev/null || true

	@echo "🧹 Removing node_modules..."
	-@find . -type d -name "node_modules" -exec rm -rf {} + 2>/dev/null || true

	@echo "🧹 Removing temporary files..."
	-@find . -type f -name "*.tmp" -delete 2>/dev/null || true
	-@find . -type f -name "*.log" -delete 2>/dev/null || true

	@echo ""
	@echo "✅ Reset complete! Run 'make setup' to reinitialize."

dev: ## Start development server with auto-reload
	@echo "🔄 Starting InferaDB engine with auto-reload..."
	@$(CARGO) watch -x 'run --bin inferadb-engine'

doc: ## Generate and open documentation (Rustdoc + API docs)
	@echo "📚 Generating documentation..."
	@$(CARGO) doc --workspace --no-deps
	@./scripts/generate-docs.sh

coverage: ## Generate code coverage report
	@$(CARGO) llvm-cov --workspace --html
	@echo "📊 Coverage report generated at target/llvm-cov/html/index.html"

bench: ## Run benchmarks
	@echo "⚡ Running benchmarks..."
	@$(CARGO) bench --workspace

# Advanced targets

fix: ## Auto-fix clippy warnings where possible
	@echo "🔧 Auto-fixing clippy warnings..."
	@$(CARGO) clippy --workspace --all-targets --fix --allow-dirty --allow-staged

expand: ## Expand macros (usage: make expand FILE=path/to/file.rs)
	@if ! $(CARGO) expand --version >/dev/null 2>&1; then \
		echo "❌ cargo-expand is not installed"; \
		echo "Install with: cargo install cargo-expand"; \
		exit 1; \
	fi
	@$(CARGO) expand -p infera-bin --bin inferadb-engine

outdated: ## Check for outdated dependencies
	@echo "🔍 Checking for outdated dependencies..."
	@$(CARGO) update --workspace --dry-run 2>&1 | grep -E "(Updating|Adding|Removing)" || echo "✅ All dependencies are up to date"

tree: ## Show dependency tree
	@$(CARGO) tree --workspace

bloat: ## Analyze binary size (requires cargo-bloat)
	@if ! $(CARGO) bloat --version >/dev/null 2>&1; then \
		echo "❌ cargo-bloat is not installed"; \
		echo "Install with: cargo install cargo-bloat"; \
		exit 1; \
	fi
	@echo "🔍 Building release binary and analyzing size..."
	@$(CARGO) bloat --release --crates

# Docker targets

docker-build: ## Build Docker image
	@echo "🐳 Building Docker image..."
	@docker build -t inferadb-engine:dev .

docker-run: ## Run Docker container
	@echo "🐳 Running Docker container..."
	@docker run -p 8080:8080 -p 8081:8081 inferadb-engine:dev

# Kubernetes targets

k8s-deploy: ## Deploy to local Kubernetes
	@echo "☸️  Deploying to Kubernetes..."
	@kubectl apply -k k8s/

k8s-delete: ## Delete from local Kubernetes
	@echo "☸️  Deleting from Kubernetes..."
	@kubectl delete -k k8s/

# CI simulation

ci: ## Simulate full CI pipeline locally
	@echo "🤖 Running full CI pipeline..."
	@$(MAKE) check
	@$(MAKE) test
	@$(MAKE) deny
	@echo "✅ CI pipeline passed! Ready to push."
