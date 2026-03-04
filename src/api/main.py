"""FastAPI application for the LLM Safety Guardrails service."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.middleware import RequestLoggingMiddleware
from src.api.routes import health_router, init_detectors, router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize detectors on startup."""
    init_detectors()
    yield


app = FastAPI(
    title="LLM Safety Guardrails API",
    description=(
        "Production safety layer for LLM applications. "
        "Provides prompt injection detection, toxicity classification, "
        "PII redaction, hallucination detection, and configurable safety policies."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging
app.add_middleware(RequestLoggingMiddleware)

# Routes
app.include_router(router)
app.include_router(health_router)
