.PHONY: install dev test lint type-check format clean run docker-build docker-run

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=src --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

lint:
	ruff check src/ tests/

lint-fix:
	ruff check --fix src/ tests/

format:
	ruff format src/ tests/

type-check:
	mypy src/

check: lint type-check test

run:
	uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

docker-build:
	docker build -t llm-guardrails-safety -f docker/Dockerfile .

docker-run:
	docker run -p 8000:8000 --env-file .env llm-guardrails-safety

clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
