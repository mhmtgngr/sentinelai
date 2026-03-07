"""Tests for configuration module."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from src.core.config import Settings, load_yaml_config


def test_settings_defaults():
    settings = Settings()
    assert settings.api_host == "0.0.0.0"
    assert settings.api_port == 8000
    assert settings.log_level == "INFO"


def test_settings_chromadb_defaults():
    settings = Settings()
    assert settings.chromadb_host == "localhost"
    assert settings.chromadb_port == 8100


def test_load_yaml_config_valid():
    data = {"key": "value", "nested": {"a": 1}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()
        result = load_yaml_config(Path(f.name))
    os.unlink(f.name)
    assert result == data


def test_load_yaml_config_missing_file():
    result = load_yaml_config(Path("/nonexistent/path.yml"))
    assert result == {}


def test_load_yaml_config_empty_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("")
        f.flush()
        result = load_yaml_config(Path(f.name))
    os.unlink(f.name)
    assert result == {}


def test_settings_default_confidence_threshold():
    settings = Settings()
    assert settings.default_confidence_threshold == 0.75


def test_settings_shadow_mode():
    settings = Settings()
    assert settings.shadow_mode is True


def test_settings_max_blast_radius():
    settings = Settings()
    assert settings.max_blast_radius == 5
