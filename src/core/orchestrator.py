"""Central orchestrator — wires up all components and manages the alert lifecycle."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from src.core.config import settings
from src.core.event_bus import (
    event_bus,
    ALERT_RECEIVED,
    ALERT_TRIAGED,
    DECISION_MADE,
    SOAR_ACTION_EXECUTED,
    EDUCATION_SENT,
)
from src.core.models import Alert, AlertStatus
from src.agents.triage_agent import TriageAgent
from src.soar.engine import SOAREngine
from src.integrations.teams import TeamsIntegration
from src.integrations.email import EmailService
from src.education.manager import EducationManager

logger = logging.getLogger(__name__)


class Orchestrator:
    """Singleton that initializes and connects all Sentinel-AI components."""

    def __init__(self) -> None:
        # Services
        self.email_service = EmailService()
        self.teams = TeamsIntegration()
        self.triage_agent = TriageAgent()
        self.soar_engine = SOAREngine()
        self.education_manager = EducationManager(
            email_service=self.email_service,
            teams=self.teams,
        )

        # In-memory alert store (swap for DB in production)
        self.alerts: dict[str, Alert] = {}
        self._decision_timers: dict[str, asyncio.Task] = {}  # type: ignore[type-arg]

        # Subscribe orchestrator-level handlers
        event_bus.subscribe(ALERT_RECEIVED, self._track_alert)
        event_bus.subscribe(ALERT_TRIAGED, self._on_triaged)
        event_bus.subscribe(DECISION_MADE, self._on_decision_made)
        event_bus.subscribe(SOAR_ACTION_EXECUTED, self._on_action_executed)
        event_bus.subscribe(EDUCATION_SENT, self._on_education_sent)

    async def ingest_alert(self, alert: Alert) -> Alert:
        """Entry point: ingest a new alert into the pipeline."""
        self.alerts[alert.id] = alert
        logger.info("Ingested alert %s: %s", alert.id, alert.title)
        await event_bus.publish(ALERT_RECEIVED, {"alert": alert.model_dump(mode="json")})
        return alert

    async def _track_alert(self, data: dict) -> None:
        alert = Alert(**data["alert"])
        self.alerts[alert.id] = alert

    async def _on_triaged(self, data: dict) -> None:
        alert = Alert(**data["alert"])
        self.alerts[alert.id] = alert
        triage = data["triage"]

        # Start decision timeout timer for alerts requiring human decision
        if triage.get("requires_human_decision"):
            alert.status = AlertStatus.AWAITING_DECISION
            self.alerts[alert.id] = alert
            self._start_decision_timer(alert.id)

        # Send email notification for high/critical alerts
        if alert.severity.value in ("high", "critical") and alert.affected_user:
            await self.email_service.send_alert_notification(
                to=alert.affected_user,
                alert_title=alert.title,
                severity=alert.severity.value,
                summary=triage.get("summary", ""),
                alert_id=alert.id,
            )

    async def _on_decision_made(self, data: dict) -> None:
        alert_id = data["decision"]["alert_id"]
        if alert_id in self._decision_timers:
            self._decision_timers[alert_id].cancel()
            del self._decision_timers[alert_id]
        if alert_id in self.alerts:
            self.alerts[alert_id].status = AlertStatus.IN_PROGRESS

    async def _on_action_executed(self, data: dict) -> None:
        action = data["action"]
        alert_id = action["alert_id"]
        if alert_id in self.alerts:
            status = action.get("status", "")
            if status == "completed":
                self.alerts[alert_id].status = AlertStatus.RESOLVED
            elif status == "failed":
                self.alerts[alert_id].status = AlertStatus.ESCALATED

    async def _on_education_sent(self, data: dict) -> None:
        logger.info("Education sent: %s", data.get("education", {}).get("id"))

    def _start_decision_timer(self, alert_id: str) -> None:
        """Start a timeout that auto-escalates if no Teams response is received."""
        timeout = settings.teams_decision_timeout_minutes * 60

        async def _timer() -> None:
            await asyncio.sleep(timeout)
            await self.teams.handle_timeout(alert_id)

        task = asyncio.create_task(_timer())
        self._decision_timers[alert_id] = task


# Singleton
_orchestrator: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator
