# Makefile for msad — all tasks run through uv.
#
# Common targets:
#   make sync       install/refresh the dev environment
#   make test       run the test suite with coverage
#   make lint       ruff check + format check + pyrefly (strict)
#   make format     apply ruff formatting and autofixes
#   make build      build the wheel and sdist into dist/
#   make publish    upload dist/ to the package index (needs credentials)
#   make clean      remove build artifacts and caches

# Use --no-sync so verification tasks don't trigger a rebuild that would need
# the (possibly unreachable) package index. Run `make sync` explicitly to
# install or update dependencies.
UV_RUN := uv run --no-sync

.DEFAULT_GOAL := help
.PHONY: help sync test lint format typecheck build publish clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

sync: ## Install/refresh the dev environment (needs the package index)
	uv sync --group dev

test: ## Run the test suite with coverage
	$(UV_RUN) pytest

lint: ## Run ruff check, ruff format --check and pyrefly (strict)
	$(UV_RUN) ruff check src/ tests/
	$(UV_RUN) ruff format --check src/ tests/
	$(UV_RUN) pyrefly check

format: ## Apply ruff autofixes and formatting
	$(UV_RUN) ruff check --fix src/ tests/
	$(UV_RUN) ruff format src/ tests/

typecheck: ## Run pyrefly (strict) only
	$(UV_RUN) pyrefly check

build: clean ## Build wheel and sdist into dist/
	uv build

publish: build ## Upload dist/ to the package index (requires credentials)
	uv publish

clean: ## Remove build artifacts and caches
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} +
