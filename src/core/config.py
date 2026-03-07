"""Central configuration loaded from environment variables."""

from __future__ import annotations

from enum import Enum
from pydantic_settings import BaseSettings
from pydantic import Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Settings(BaseSettings):
    # ── Microsoft Teams ──
    teams_webhook_url: str = ""
    teams_bot_app_id: str = ""
    teams_bot_app_secret: str = ""
    teams_tenant_id: str = ""

    # ── Email ──
    smtp_host: str = "smtp.office365.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""

    # ── API ──
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_base_url: str = "http://localhost:8000"

    # ── LLM ──
    llm_provider: str = "anthropic"
    anthropic_api_key: str = ""
    openai_api_key: str = ""

    # ── ChromaDB ──
    chroma_host: str = "localhost"
    chroma_port: int = 8100

    # ── Autonomy controls ──
    autonomous_mode: bool = True
    auto_remediate: bool = False
    require_teams_approval_severity: Severity = Severity.HIGH

    # ── Timeouts ──
    teams_decision_timeout_minutes: int = 30
    alert_dedup_window_seconds: int = 300

    log_level: str = "INFO"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
