"""Configuration management for Sentinel-AI.

Loads settings from environment variables / .env file.
Adapter and agent configs loaded from YAML files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment."""

    # LLM
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"

    # Database
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_ai"

    # ChromaDB
    chromadb_host: str = "localhost"
    chromadb_port: int = 8100

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_secret_key: str = "change-me-in-production"

    # Agent defaults
    default_confidence_threshold: float = 0.75
    max_blast_radius: int = 5
    shadow_mode: bool = True

    # Observability
    log_level: str = "INFO"
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"

    # Config paths
    config_dir: Path = Field(default=Path("config"))

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


def load_yaml_config(path: Path) -> dict[str, Any]:
    """Load a YAML configuration file."""
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_adapter_config(config_dir: Path) -> dict[str, Any]:
    """Load adapter configurations from adapters.yaml."""
    return load_yaml_config(config_dir / "adapters.yaml")


def load_agent_config(config_dir: Path) -> dict[str, Any]:
    """Load agent configurations from agents.yaml."""
    return load_yaml_config(config_dir / "agents.yaml")
