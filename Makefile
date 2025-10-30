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

.PHONY: help setup test test-watch test-unit test-integration check fmt lint audit deny build release clean dev doc coverage bench

# Use mise exec if available, otherwise use system cargo
CARGO := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- cargo" || echo "cargo")

# Default target - show help
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "InferaDB Development Commands"
	@echo ""
	@echo "Common tasks:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Use standard cargo commands for more options:"
	@echo "  cargo test --help"
	@echo "  cargo build --help"
	@echo ""

setup: ## One-time development environment setup
	@echo "🔧 Setting up development environment..."
	@mise trust && mise install
	@mise run setup

test: ## Run all tests (using nextest)
	@$(CARGO) nextest run --workspace

test-watch: ## Run tests in watch mode
	@$(CARGO) watch -x 'nextest run --workspace'

test-unit: ## Run unit tests only
	@$(CARGO) nextest run --lib --workspace

test-integration: ## Run integration tests only
	@$(CARGO) nextest run --test '*' --workspace

check: ## Run all checks (fmt, clippy, test, audit)
	@echo "🔍 Running format check..."
	@$(CARGO) fmt --check
	@echo "🔍 Running clippy..."
	@$(CARGO) clippy --workspace --all-targets -- -D warnings
	@echo "🧪 Running tests..."
	@$(CARGO) test --workspace
	@echo "🔒 Running security audit..."
	@$(CARGO) audit
	@echo "✅ All checks passed!"

fmt: ## Format code with rustfmt
	@$(CARGO) fmt --all

lint: ## Run clippy linter
	@$(CARGO) clippy --workspace --all-targets -- -D warnings

audit: ## Run security audit
	@$(CARGO) audit

deny: ## Check dependencies with cargo-deny
	@$(CARGO) deny check

build: ## Build debug binary
	@$(CARGO) build

release: ## Build optimized release binary
	@$(CARGO) build --release --workspace

clean: ## Clean build artifacts
	@$(CARGO) clean

dev: ## Start development server with auto-reload
	@$(CARGO) watch -x 'run --bin inferadb'

doc: ## Generate and open documentation
	@$(CARGO) doc --workspace --open --no-deps

doc-api: ## Generate API documentation (Rustdoc)
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
	@$(CARGO) expand --bin inferadb

outdated: ## Check for outdated dependencies
	@$(CARGO) outdated --workspace

tree: ## Show dependency tree
	@$(CARGO) tree --workspace

bloat: ## Analyze binary size (requires cargo-bloat)
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

ci: ## Simulate CI checks locally
	@echo "🤖 Running CI checks locally..."
	@$(MAKE) fmt
	@$(MAKE) lint
	@$(MAKE) test
	@$(MAKE) audit
	@$(MAKE) deny
	@echo "✅ CI checks passed! Ready to push."
