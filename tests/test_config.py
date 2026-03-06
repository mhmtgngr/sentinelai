"""Tests for configuration management."""

import os
import pytest
from src.core.config import SentinelConfig, LLMConfig, ChromaConfig, APIConfig


def test_default_config():
    config = SentinelConfig()
    assert config.llm.provider == "claude"
    assert config.chroma.port == 8000
    assert config.api.port == 8080
    assert config.heartbeat_interval == 60


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-4")
    monkeypatch.setenv("API_PORT", "9090")
    monkeypatch.setenv("HEARTBEAT_INTERVAL", "120")

    config = SentinelConfig.from_env()
    assert config.llm.provider == "openai"
    assert config.llm.model == "gpt-4"
    assert config.api.port == 9090
    assert config.heartbeat_interval == 120


def test_config_from_yaml():
    config = SentinelConfig.from_yaml("config")
    # Should load without error even with all adapters commented out
    assert isinstance(config.adapters, list)
    assert isinstance(config.agents, dict)
