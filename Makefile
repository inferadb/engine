# Makefile for InferaDB development
# Provides convenient shortcuts for common cargo commands
#
# Quick start:
#   make setup    - One-time setup (installs tools)
#   make test     - Run all tests
#   make check    - Run all quality checks
#   make dev      - Start development server with watch
#
# Use 'make help' to see all available commands

.PHONY: help setup test test-integration test-leaks test-stress test-load test-fdb test-aws test-gcp test-azure check format lint audit deny run build release clean nuke dev doc coverage bench expand outdated tree bloat fix docker-build docker-run k8s-deploy k8s-delete ci

# Use mise exec if available, otherwise use system cargo
CARGO := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- cargo" || echo "cargo")
PRETTIER := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- prettier" || echo "prettier")
TAPLO := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- taplo" || echo "taplo")

# Default target - show help
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "InferaDB Development Commands"
	@echo ""
	@echo "Setup & Development:"
	@grep -E '^(setup|run|dev|build|release|clean|nuke):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
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
	@mise trust && mise install
	@mise run setup

test: ## Run unit tests
	@$(CARGO) nextest run --lib --workspace

test-integration: ## Run integration tests
	@$(CARGO) nextest run --test '*' --workspace

test-leaks: ## Run memory leak detection tests
	@$(CARGO) test --test memory_leak_tests --package infera-api

test-load: ## Run load/stress tests (ignored by default)
	@$(CARGO) test --package infera-core --test performance_load -- --ignored --test-threads=1

test-fdb: ## Run FoundationDB integration tests (requires Docker)
	@./docker/fdb-integration-tests/test.sh

test-aws: ## Run AWS Secrets Manager tests (requires credentials)
	@$(CARGO) test --package infera-config --features aws-secrets -- --test-threads=1

test-gcp: ## Run GCP Secret Manager tests (requires credentials)
	@$(CARGO) test --package infera-config --features gcp-secrets -- --test-threads=1

test-azure: ## Run Azure Key Vault tests (requires credentials)
	@$(CARGO) test --package infera-config --features azure-secrets -- --test-threads=1

check: ## Run code quality checks (format, lint, audit)
	@echo "🔍 Running code quality checks..."
	@$(MAKE) format
	@$(MAKE) lint
	@$(MAKE) audit
	@echo "✅ All checks passed!"

format: ## Format code (Prettier, Taplo, rustfmt)
	@$(PRETTIER) --write "**/*.{md,yml,yaml,json}" --log-level warn || true
	@$(TAPLO) fmt
	@$(CARGO) +nightly fmt --all

lint: ## Run clippy linter
	@$(CARGO) clippy --workspace --all-targets -- -D warnings

audit: ## Run security audit
	@$(CARGO) audit

deny: ## Check dependencies with cargo-deny
	@$(CARGO) deny check

run: ## Run the inferadb server (debug mode)
	@$(CARGO) run --bin inferadb

build: ## Build debug binary
	@$(CARGO) build

release: ## Build optimized release binary
	@$(CARGO) build --release --workspace

clean: ## Clean build artifacts
	@$(CARGO) clean

nuke: ## Nuke the dev environment - reset to pristine dev environment
	@echo "☢️  NUCLEAR CLEANUP - This will remove ALL dev artifacts!"
	@echo "This will:"
	@echo "  - Stop and remove all Docker containers"
	@echo "  - Remove all Docker volumes and networks"
	@echo "  - Clean cargo build artifacts"
	@echo "  - Clear cargo registry cache"
	@echo "  - Clear mise/asdf tool versions"
	@echo "  - Remove node_modules (if any)"
	@echo ""
	@read -p "Are you sure? Type 'yes' to continue: " confirm && [ "$$confirm" = "yes" ] || (echo "Cancelled." && exit 1)
	@echo ""
	@echo "🧹 Stopping and removing Docker containers..."
	-@docker ps -aq | xargs -r docker stop 2>/dev/null || true
	-@docker ps -aq | xargs -r docker rm 2>/dev/null || true
	@echo "🧹 Removing Docker volumes..."
	-@docker volume ls -q | grep -E 'inferadb|fdb' | xargs -r docker volume rm 2>/dev/null || true
	@echo "🧹 Removing Docker networks..."
	-@docker network ls -q | grep -E 'inferadb|fdb' | xargs -r docker network rm 2>/dev/null || true
	@echo "🧹 Cleaning FDB test environment..."
	-@./docker/fdb-integration-tests/cleanup.sh 2>/dev/null || true
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
	@echo "✅ Nuclear cleanup complete! Run 'make setup' to reinitialize."

dev: ## Start development server with auto-reload
	@$(CARGO) watch -x 'run --bin inferadb'

doc: ## Generate and open documentation (Rustdoc + API docs)
	@$(CARGO) doc --workspace --no-deps
	@./scripts/generate-docs.sh

coverage: ## Generate code coverage report
	@$(CARGO) llvm-cov --workspace --html
	@echo "📊 Coverage report generated at target/llvm-cov/html/index.html"

bench: ## Run benchmarks
	@$(CARGO) bench --workspace

# Advanced targets

fix: ## Auto-fix clippy warnings where possible
	@$(CARGO) clippy --workspace --all-targets --fix --allow-dirty --allow-staged

expand: ## Expand macros (usage: make expand FILE=path/to/file.rs)
	@if ! $(CARGO) expand --version >/dev/null 2>&1; then \
		echo "❌ cargo-expand is not installed"; \
		echo "Install with: cargo install cargo-expand"; \
		exit 1; \
	fi
	@$(CARGO) expand --bin inferadb

outdated: ## Check for outdated dependencies
	@if ! $(CARGO) outdated --version >/dev/null 2>&1; then \
		echo "❌ cargo-outdated is not installed"; \
		echo "Install with: cargo install cargo-outdated"; \
		exit 1; \
	fi
	@$(CARGO) outdated --workspace

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
	@docker build -t inferadb:dev .

docker-run: ## Run Docker container
	@docker run -p 8080:8080 -p 8081:8081 inferadb:dev

# Kubernetes targets

k8s-deploy: ## Deploy to local Kubernetes
	@kubectl apply -k k8s/

k8s-delete: ## Delete from local Kubernetes
	@kubectl delete -k k8s/

# CI simulation

ci: ## Simulate full CI pipeline locally
	@echo "🤖 Running full CI pipeline..."
	@$(MAKE) check
	@$(MAKE) test
	@$(MAKE) deny
	@echo "✅ CI pipeline passed! Ready to push."
