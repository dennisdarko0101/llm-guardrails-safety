# Multi-stage build for LLM Safety Guardrails API
# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

# Stage 2: Runtime
FROM python:3.12-slim

# Security: run as non-root
RUN groupadd -r guardrails && useradd -r -g guardrails guardrails

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source
COPY pyproject.toml .
COPY src/ src/

# Install the project itself
RUN pip install --no-cache-dir --no-deps -e .

# Switch to non-root user
USER guardrails

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
