"""Application settings using Pydantic Settings for environment-based configuration."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SafetyLevel(str, Enum):
    STRICT = "strict"
    MODERATE = "moderate"
    PERMISSIVE = "permissive"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="GUARDRAILS_",
    )

    # API Keys
    anthropic_api_key: str = Field(default="", description="Anthropic API key for Claude")
    openai_api_key: str = Field(default="", description="OpenAI API key")

    # Safety Configuration
    safety_level: SafetyLevel = Field(
        default=SafetyLevel.MODERATE,
        description="Global safety level: strict, moderate, or permissive",
    )
    max_input_length: int = Field(
        default=10000,
        description="Maximum allowed input length in characters",
    )
    enable_pii_redaction: bool = Field(
        default=True,
        description="Enable automatic PII detection and redaction",
    )
    toxicity_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Threshold above which content is flagged as toxic",
    )
    injection_sensitivity: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="Sensitivity level for prompt injection detection",
    )

    # LLM-Based Detection
    enable_llm_detection: bool = Field(
        default=False,
        description="Enable LLM-based detection (requires API keys, slower but more accurate)",
    )
    llm_provider: Literal["anthropic", "openai"] = Field(
        default="anthropic",
        description="LLM provider for AI-based classification",
    )
    llm_model: str = Field(
        default="claude-sonnet-4-20250514",
        description="Model name for LLM-based detection",
    )

    # Server
    host: str = Field(default="0.0.0.0", description="API server host")
    port: int = Field(default=8000, description="API server port")

    # Logging
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging level")
    log_json: bool = Field(default=True, description="Output logs in JSON format")

    # Feature Flags
    enable_topic_boundary: bool = Field(default=True, description="Enable topic boundary checking")
    enable_hallucination_detection: bool = Field(
        default=False,
        description="Enable hallucination detection (requires LLM)",
    )
    enable_output_validation: bool = Field(default=True, description="Enable output validation")


def get_settings() -> Settings:
    """Get cached application settings."""
    return Settings()
