"""Automated incident response agent."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from src.agents.base_agent import AgentCapability, AgentResult, BaseAgent
from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


@dataclass
class Incident:
    incident_id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    severity: str = "medium"
    status: str = "open"
    attack_type: str = "unknown"
    source_events: list[str] = field(default_factory=list)
    actions_taken: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Response playbook definitions
PLAYBOOKS = {
    "brute_force": [
        {"action": "block_ip", "params": {"duration": 3600}, "severity_threshold": "medium"},
        {"action": "reset_credentials", "params": {}, "severity_threshold": "high"},
        {"action": "notify_soc", "params": {"channel": "slack"}, "severity_threshold": "low"},
    ],
    "malware": [
        {"action": "isolate_host", "params": {}, "severity_threshold": "medium"},
        {"action": "collect_forensics", "params": {}, "severity_threshold": "medium"},
        {"action": "block_ip", "params": {"duration": 86400}, "severity_threshold": "low"},
        {"action": "notify_soc", "params": {"channel": "slack", "priority": "high"}, "severity_threshold": "low"},
    ],
    "data_exfiltration": [
        {"action": "block_ip", "params": {"duration": 86400}, "severity_threshold": "low"},
        {"action": "isolate_host", "params": {}, "severity_threshold": "medium"},
        {"action": "notify_soc", "params": {"channel": "slack", "priority": "critical"}, "severity_threshold": "low"},
    ],
    "lateral_movement": [
        {"action": "isolate_host", "params": {}, "severity_threshold": "medium"},
        {"action": "revoke_sessions", "params": {}, "severity_threshold": "medium"},
        {"action": "notify_soc", "params": {"channel": "slack", "priority": "high"}, "severity_threshold": "low"},
    ],
    "default": [
        {"action": "notify_soc", "params": {"channel": "slack"}, "severity_threshold": "low"},
    ],
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class IncidentResponderAgent(BaseAgent):
    """Automates incident response using playbook-driven actions."""

    name = "incident_responder"
    capability = AgentCapability.INCIDENT_RESPONSE

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        super().__init__(event_bus, config)
        self._incidents: dict[str, Incident] = {}

    async def process(self, event: Event) -> AgentResult:
        """Create or update an incident from a threat event and execute playbook."""
        data = event.data
        attack_type = data.get("attack_type", data.get("type", "unknown"))
        severity = data.get("severity", "medium")

        # Create incident
        incident = Incident(
            title=f"{attack_type} detected from {data.get('source_ip', 'unknown')}",
            severity=severity,
            attack_type=attack_type,
            source_events=[event.event_id],
        )
        incident.timeline.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "action": "incident_created",
            "details": data,
        })
        self._incidents[incident.incident_id] = incident

        await self.event_bus.publish(Event(
            event_type=EventType.INCIDENT_CREATED,
            data={
                "incident_id": incident.incident_id,
                "title": incident.title,
                "severity": incident.severity,
            },
            source=self.name,
        ))

        # Execute playbook
        actions_executed = await self._execute_playbook(incident)

        return AgentResult(
            agent_name=self.name,
            action="respond",
            success=True,
            data={
                "incident_id": incident.incident_id,
                "actions_executed": actions_executed,
                "severity": severity,
            },
        )

    async def run_autonomous(self) -> list[AgentResult]:
        """Check open incidents for staleness and escalate if needed."""
        results = []
        for incident in self._incidents.values():
            if incident.status == "open":
                age = (datetime.now(timezone.utc) - incident.created_at).total_seconds()
                if age > 3600 and incident.severity in ("high", "critical"):
                    incident.timeline.append({
                        "time": datetime.now(timezone.utc).isoformat(),
                        "action": "auto_escalated",
                        "details": "Open critical incident older than 1 hour",
                    })
                    results.append(AgentResult(
                        agent_name=self.name,
                        action="escalate",
                        success=True,
                        data={"incident_id": incident.incident_id},
                    ))
        return results

    async def _execute_playbook(self, incident: Incident) -> list[dict]:
        playbook = PLAYBOOKS.get(incident.attack_type, PLAYBOOKS["default"])
        executed = []

        for step in playbook:
            if SEVERITY_ORDER.get(incident.severity, 0) >= SEVERITY_ORDER.get(step["severity_threshold"], 0):
                action_record = {
                    "action": step["action"],
                    "params": step["params"],
                    "status": "requested",
                }
                incident.actions_taken.append(action_record)
                incident.timeline.append({
                    "time": datetime.now(timezone.utc).isoformat(),
                    "action": step["action"],
                    "details": step["params"],
                })

                # Request action execution
                await self.event_bus.publish(Event(
                    event_type=EventType.ACTION_REQUESTED,
                    data={
                        "action": step["action"],
                        "params": step["params"],
                        "incident_id": incident.incident_id,
                        "severity": incident.severity,
                    },
                    source=self.name,
                ))
                executed.append(action_record)

        return executed

    def get_incident(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_incidents(self, status: str | None = None) -> list[Incident]:
        incidents = list(self._incidents.values())
        if status:
            incidents = [i for i in incidents if i.status == status]
        return incidents

    def close_incident(self, incident_id: str, resolution: str) -> bool:
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        incident.status = "closed"
        incident.updated_at = datetime.now(timezone.utc)
        incident.timeline.append({
            "time": datetime.now(timezone.utc).isoformat(),
            "action": "incident_closed",
            "details": resolution,
        })
        return True
