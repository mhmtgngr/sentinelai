"""Abstract adapter interface for security product integrations."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class SecurityEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    source: str = ""
    event_type: str = ""
    severity: str = "info"
    description: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    source_ip: str = ""
    destination_ip: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    rule_id: str = ""
    rule_name: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""


@dataclass
class ActionResult:
    success: bool
    action: str
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)


class BaseSecurityAdapter(ABC):
    """Abstract base for all security product adapters."""

    product_type: str = ""
    vendor: str = ""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.endpoint = config.get("endpoint", "")
        self._connected = False
        self.logger = logging.getLogger(f"sentinel.adapter.{self.vendor}")

    async def connect(self) -> None:
        """Establish connection to the security product."""
        self.logger.info("Connecting to %s at %s", self.vendor, self.endpoint)
        await self._authenticate()
        self._connected = True
        self.logger.info("Connected to %s", self.vendor)

    async def disconnect(self) -> None:
        """Disconnect from the security product."""
        self._connected = False
        self.logger.info("Disconnected from %s", self.vendor)

    @abstractmethod
    async def _authenticate(self) -> None:
        """Authenticate with the security product API."""
        ...

    @abstractmethod
    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Retrieve security events from the product."""
        ...

    @abstractmethod
    async def health_check(self) -> HealthStatus:
        """Check connectivity and health of the security product."""
        ...

    @property
    def is_connected(self) -> bool:
        return self._connected

    def _build_event(self, raw: dict, **overrides: Any) -> dict[str, Any]:
        """Helper to build a normalized event dict from raw product data."""
        event = SecurityEvent(
            source=f"{self.vendor}/{self.product_type}",
            raw_data=raw,
            **overrides,
        )
        return {
            "event_id": event.event_id,
            "source": event.source,
            "event_type": event.event_type,
            "severity": event.severity,
            "description": event.description,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "timestamp": event.timestamp.isoformat(),
            "rule_id": event.rule_id,
            "rule_name": event.rule_name,
            "mitre_tactic": event.mitre_tactic,
            "mitre_technique": event.mitre_technique,
            "raw_data": event.raw_data,
        }
