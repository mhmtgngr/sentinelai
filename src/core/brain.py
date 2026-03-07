"""Central AI Brain — Multi-agent coordinator for Sentinel-AI.

Manages the reactive and proactive pipelines, priority queue,
task deduplication, conflict resolution, and action validation.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

from src.agents.base_agent import BaseAgent
from src.core.event_bus import EventBus
from src.core.models import (
    ActionType,
    AgentDecision,
    Alert,
    HandoffPayload,
    SecurityEvent,
    Severity,
)
from src.integrations.adapter_registry import AdapterRegistry

logger = logging.getLogger(__name__)

SEVERITY_PRIORITY = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 10,
    Severity.MEDIUM: 20,
    Severity.LOW: 30,
    Severity.INFO: 40,
}

AGENT_AUTHORITY = {
    "compliance_auditor": 1,
    "incident_responder": 2,
    "threat_hunter": 3,
    "forensic_analyst": 4,
    "triage": 5,
    "vuln_scanner": 6,
}

ACTION_CORROBORATION_REQUIRED = {
    ActionType.BLOCK_IP,
    ActionType.DISABLE_ACCOUNT,
    ActionType.ISOLATE_HOST,
    ActionType.QUARANTINE_FILE,
    ActionType.FORCE_PASSWORD_RESET,
}


class Brain:
    """Multi-agent coordinator managing all security pipelines.

    Responsibilities:
    - Route alerts through reactive pipeline (triage -> hunt -> respond)
    - Schedule proactive pipelines (scans, hunts, audits)
    - Deduplicate alerts by IOC overlap
    - Resolve conflicts between agent decisions
    - Validate actions before execution
    """

    def __init__(
        self,
        event_bus: EventBus,
        agents: dict[str, BaseAgent],
        adapter_registry: AdapterRegistry,
        confidence_threshold: float = 0.75,
        max_blast_radius: int = 5,
        shadow_mode: bool = True,
    ) -> None:
        self._event_bus = event_bus
        self._agents = agents
        self._adapter_registry = adapter_registry
        self._confidence_threshold = confidence_threshold
        self._max_blast_radius = max_blast_radius
        self._shadow_mode = shadow_mode

        self._alert_queue: asyncio.PriorityQueue[tuple[int, str, Alert]] = asyncio.PriorityQueue()
        self._dedup_index: dict[str, list[str]] = defaultdict(list)
        self._active_alerts: dict[str, Alert] = {}
        self._decisions: dict[str, list[AgentDecision]] = defaultdict(list)

        self._semaphores: dict[str, asyncio.Semaphore] = {
            "triage": asyncio.Semaphore(10),
            "threat_hunter": asyncio.Semaphore(3),
            "incident_responder": asyncio.Semaphore(1),
            "compliance_auditor": asyncio.Semaphore(2),
            "forensic_analyst": asyncio.Semaphore(2),
            "vuln_scanner": asyncio.Semaphore(1),
        }

    async def start(self) -> None:
        """Subscribe to event bus topics and start processing."""
        self._event_bus.subscribe("alert.new", self._handle_new_alert)
        self._event_bus.subscribe("investigation.requested", self._handle_investigation)
        logger.info("Brain coordinator started (shadow_mode=%s)", self._shadow_mode)

    async def _handle_new_alert(self, data: dict[str, Any]) -> None:
        """Entry point for new alerts from the event bus."""
        event = SecurityEvent(**data) if not isinstance(data, SecurityEvent) else data
        alert = Alert(events=[event], priority=SEVERITY_PRIORITY.get(event.severity, 40))

        existing = self._check_deduplication(alert)
        if existing is not None:
            logger.info("Alert deduplicated into existing alert %s", existing.id)
            existing.events.extend(alert.events)
            return

        self._active_alerts[alert.id] = alert
        await self._alert_queue.put((alert.priority, alert.id, alert))
        asyncio.create_task(self._process_alert(alert))

    async def _handle_investigation(self, data: dict[str, Any]) -> None:
        """Handle manual investigation requests (from OpenClaw skills)."""
        alert = Alert(priority=data.get("priority", 10))
        self._active_alerts[alert.id] = alert
        asyncio.create_task(self._process_alert(alert))

    async def _process_alert(self, alert: Alert) -> None:
        """Run the reactive pipeline for an alert."""
        try:
            await self._run_reactive_pipeline(alert)
        except Exception:
            logger.exception("Pipeline failed for alert %s", alert.id)
            await self._event_bus.publish(
                "alert.error",
                {"alert_id": alert.id, "error": "pipeline_failure"},
            )

    async def _run_reactive_pipeline(self, alert: Alert) -> None:
        """Triage -> Hunt -> Respond (with Forensics in parallel)."""
        # Step 1: Triage
        triage_decision = await self._run_agent("triage", alert)
        if triage_decision is None:
            return

        self._decisions[alert.id].append(triage_decision)
        await self._event_bus.publish("alert.triaged", {
            "alert_id": alert.id,
            "verdict": triage_decision.reasoning_trace,
            "confidence": triage_decision.confidence,
        })

        if triage_decision.confidence < self._confidence_threshold:
            logger.info("Alert %s below confidence threshold, skipping", alert.id)
            return

        # Step 2: Threat Hunt + Forensics (parallel)
        hunt_task = asyncio.create_task(self._run_agent("threat_hunter", alert))
        forensic_task = asyncio.create_task(self._run_agent("forensic_analyst", alert))

        hunt_decision = await hunt_task
        if hunt_decision:
            self._decisions[alert.id].append(hunt_decision)
            await self._event_bus.publish("threat.confirmed", {
                "alert_id": alert.id,
                "confidence": hunt_decision.confidence,
            })

        forensic_decision = await forensic_task
        if forensic_decision:
            self._decisions[alert.id].append(forensic_decision)

        # Step 3: Incident Response
        if hunt_decision and hunt_decision.confidence >= self._confidence_threshold:
            respond_decision = await self._run_agent("incident_responder", alert)
            if respond_decision:
                self._decisions[alert.id].append(respond_decision)
                for action in respond_decision.recommended_actions:
                    if self._validate_action(action, respond_decision):
                        if self._shadow_mode:
                            logger.info("SHADOW MODE: Would execute %s on %s", action.get("type"), action.get("target"))
                        else:
                            await self._event_bus.publish("action.executed", {
                                "alert_id": alert.id,
                                "action": action,
                            })

        # Step 4: Compliance check (async)
        asyncio.create_task(self._run_agent("compliance_auditor", alert))

    async def _run_agent(self, agent_id: str, alert: Alert) -> AgentDecision | None:
        """Run a specific agent with semaphore control."""
        agent = self._agents.get(agent_id)
        if agent is None:
            logger.warning("Agent '%s' not registered", agent_id)
            return None

        semaphore = self._semaphores.get(agent_id)
        if semaphore is None:
            return await agent.execute(alert)

        async with semaphore:
            return await agent.execute(alert)

    def _check_deduplication(self, alert: Alert) -> Alert | None:
        """Check if this alert overlaps with an existing active alert."""
        new_iocs: set[str] = set()
        for event in alert.events:
            for ioc in event.iocs:
                key = f"{ioc.type}:{ioc.value}"
                new_iocs.add(key)

        for ioc_key in new_iocs:
            existing_alert_ids = self._dedup_index.get(ioc_key, [])
            for alert_id in existing_alert_ids:
                existing = self._active_alerts.get(alert_id)
                if existing is not None:
                    existing_iocs: set[str] = set()
                    for event in existing.events:
                        for ioc in event.iocs:
                            existing_iocs.add(f"{ioc.type}:{ioc.value}")

                    overlap = new_iocs & existing_iocs
                    if len(overlap) / max(len(new_iocs), 1) > 0.5:
                        return existing

        for ioc_key in new_iocs:
            self._dedup_index[ioc_key].append(alert.id)

        return None

    def _validate_action(self, action: dict[str, Any], decision: AgentDecision) -> bool:
        """Validate an action against safety controls."""
        action_type_str = action.get("type", "")
        try:
            action_type = ActionType(action_type_str)
        except ValueError:
            logger.warning("Invalid action type: %s", action_type_str)
            return False

        if decision.confidence < self._confidence_threshold:
            logger.info("Action rejected: confidence %.2f < threshold %.2f", decision.confidence, self._confidence_threshold)
            return False

        if action_type in ACTION_CORROBORATION_REQUIRED:
            if len(decision.data_sources_consulted) < 2:
                logger.info("Action rejected: corroboration required but only %d sources", len(decision.data_sources_consulted))
                return False

        return True

    def _resolve_conflict(self, decisions: list[AgentDecision]) -> AgentDecision:
        """Resolve conflicting agent decisions using authority hierarchy."""
        if not decisions:
            raise ValueError("No decisions to resolve")

        if len(decisions) == 1:
            return decisions[0]

        sorted_decisions = sorted(
            decisions,
            key=lambda d: AGENT_AUTHORITY.get(d.agent_id, 99),
        )

        return sorted_decisions[0]

    @property
    def active_alert_count(self) -> int:
        return len(self._active_alerts)

    @property
    def queue_depth(self) -> int:
        return self._alert_queue.qsize()
