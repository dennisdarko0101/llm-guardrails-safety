# Contributing

## Development Setup

```bash
git clone https://github.com/yourusername/llm-guardrails-safety.git
cd llm-guardrails-safety
pip install -e ".[dev]"
```

## Running Tests

```bash
make test             # All tests with coverage
make test-unit        # Unit tests only
make test-integration # Integration tests only
```

## Code Quality

```bash
make lint       # Check linting
make lint-fix   # Auto-fix lint issues
make format     # Format code
make type-check # Run mypy
make check      # All checks
```

## Pull Request Process

1. Create a feature branch from `main`
2. Write tests for new functionality
3. Ensure all tests pass and coverage stays above 80%
4. Run `make check` before submitting
5. Open a PR with a clear description

## Code Style

- Python 3.11+ with type annotations
- Ruff for linting and formatting (line length: 100)
- mypy strict mode
- Dataclasses for data models, Pydantic for API schemas
- Docstrings on public classes and functions

## Adding New Detection Patterns

1. Add patterns to the relevant detector in `src/detection/`
2. Add test cases in `tests/unit/`
3. Update documentation in `docs/SAFETY_GUIDE.md`

## Adding New API Endpoints

1. Add Pydantic models to `src/api/schemas.py`
2. Add route handler to `src/api/routes.py`
3. Add integration tests to `tests/integration/test_api.py`
4. Update API examples in `README.md`
