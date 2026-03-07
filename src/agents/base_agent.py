"""Abstract base for all Sentinel-AI agents."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from src.core.event_bus import Event, EventBus


class AgentCapability(str, Enum):
    TRIAGE = "triage"
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE = "compliance"
    FORENSICS = "forensics"
    VULNERABILITY_SCAN = "vulnerability_scan"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    ASSET_MANAGEMENT = "asset_management"


@dataclass
class AgentResult:
    agent_name: str
    action: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    result_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None


class BaseAgent(ABC):
    """Abstract base class for all Sentinel-AI security agents."""

    name: str = "base"
    capability: AgentCapability = AgentCapability.TRIAGE

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        self.event_bus = event_bus
        self.config = config or {}
        self.logger = logging.getLogger(f"sentinel.agent.{self.name}")
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the agent. Override for custom setup."""
        self._initialized = True
        self.logger.info("Agent %s initialized", self.name)

    @abstractmethod
    async def process(self, event: Event) -> AgentResult:
        """Process an incoming event. Must be implemented by all agents."""
        ...

    @abstractmethod
    async def run_autonomous(self) -> list[AgentResult]:
        """Run autonomous checks (called during heartbeat). Must be implemented."""
        ...

    async def emit_result(self, result: AgentResult) -> None:
        """Publish an agent result as an event."""
        from src.core.event_bus import EventType
        event_type = (
            EventType.ACTION_EXECUTED if result.success else EventType.ACTION_FAILED
        )
        await self.event_bus.publish(Event(
            event_type=event_type,
            data={"result": result.__dict__},
            source=self.name,
        ))
