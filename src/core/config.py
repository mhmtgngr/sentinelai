"""Configuration management for Sentinel-AI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class LLMConfig:
    provider: str = "claude"
    api_key: str = ""
    model: str = "claude-sonnet-4-20250514"
    ollama_base_url: str = "http://localhost:11434"


@dataclass
class ChromaConfig:
    host: str = "localhost"
    port: int = 8000
    collection: str = "sentinel_memory"


@dataclass
class APIConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass
class SentinelConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    chroma: ChromaConfig = field(default_factory=ChromaConfig)
    api: APIConfig = field(default_factory=APIConfig)
    log_level: str = "INFO"
    log_format: str = "json"
    heartbeat_interval: int = 60
    adapters: list[dict] = field(default_factory=list)
    agents: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> SentinelConfig:
        """Load configuration from environment variables."""
        return cls(
            llm=LLMConfig(
                provider=os.getenv("LLM_PROVIDER", "claude"),
                api_key=os.getenv("LLM_API_KEY", ""),
                model=os.getenv("LLM_MODEL", "claude-sonnet-4-20250514"),
                ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            ),
            chroma=ChromaConfig(
                host=os.getenv("CHROMA_HOST", "localhost"),
                port=int(os.getenv("CHROMA_PORT", "8000")),
                collection=os.getenv("CHROMA_COLLECTION", "sentinel_memory"),
            ),
            api=APIConfig(
                host=os.getenv("API_HOST", "0.0.0.0"),
                port=int(os.getenv("API_PORT", "8080")),
            ),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_format=os.getenv("LOG_FORMAT", "json"),
            heartbeat_interval=int(os.getenv("HEARTBEAT_INTERVAL", "60")),
        )

    @classmethod
    def from_yaml(cls, config_dir: str | Path = "config") -> SentinelConfig:
        """Load configuration from YAML files and overlay env vars."""
        config = cls.from_env()
        config_dir = Path(config_dir)

        adapters_file = config_dir / "adapters.yaml"
        if adapters_file.exists():
            with open(adapters_file) as f:
                data = yaml.safe_load(f) or {}
                config.adapters = data.get("adapters") or []

        agents_file = config_dir / "agents.yaml"
        if agents_file.exists():
            with open(agents_file) as f:
                data = yaml.safe_load(f) or {}
                config.agents = data.get("agents") or {}

        return config
