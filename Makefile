.PHONY: install dev test test-unit test-integration lint lint-fix format type-check check run docker-build docker-run docker-compose-up clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install package
	pip install -e .

dev: ## Install with dev dependencies
	pip install -e ".[dev]"

test: ## Run all tests with coverage
	pytest tests/ -v --cov=src --cov-report=term-missing --cov-fail-under=80

test-unit: ## Run unit tests only
	pytest tests/unit/ -v

test-integration: ## Run integration tests only
	pytest tests/integration/ -v

lint: ## Run ruff linter
	ruff check src/ tests/

lint-fix: ## Auto-fix lint issues
	ruff check --fix src/ tests/

format: ## Format code with ruff
	ruff format src/ tests/

type-check: ## Run mypy type checking
	mypy src/ --ignore-missing-imports

check: lint type-check test ## Run all checks (lint + type-check + test)

run: ## Start API server (development)
	uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

docker-build: ## Build Docker image
	docker build -t llm-guardrails-safety -f docker/Dockerfile .

docker-run: ## Run Docker container
	docker run -p 8000:8000 --env-file .env llm-guardrails-safety

docker-compose-up: ## Start with docker-compose
	cd docker && docker-compose up --build

clean: ## Remove build artifacts and caches
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
