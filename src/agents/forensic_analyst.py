"""Forensic Analyst Agent — Deep investigation and evidence collection.

Builds chronological timelines, collects evidence with chain of custody,
and performs root cause analysis.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from src.agents.base_agent import BaseAgent
from src.core.models import AgentDecision, Alert, TimelineEntry

logger = logging.getLogger(__name__)


class ForensicAnalystAgent(BaseAgent):
    """Deep forensic investigation agent.

    Collects evidence from multiple sources, builds timelines,
    and analyzes root cause.
    """

    def __init__(
        self,
        adapter_registry: Any = None,
        llm_client: Any = None,
        llm_model: str = "claude-sonnet-4-6",
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_id="forensic_analyst", timeout_seconds=300, **kwargs)
        self._adapter_registry = adapter_registry
        self._llm_client = llm_client
        self._llm_model = llm_model

    @property
    def capabilities(self) -> list[str]:
        return ["investigate", "timeline", "evidence"]

    async def process(self, alert: Alert) -> AgentDecision:
        """Conduct forensic investigation of an alert."""
        timeline = self._build_timeline(alert)
        evidence = await self._collect_evidence(alert)

        if self._llm_client is not None:
            root_cause = await self._analyze_root_cause(alert, timeline, evidence)
        else:
            root_cause = "LLM unavailable — manual root cause analysis required"

        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=0.75,
            reasoning_trace=[
                f"Timeline entries: {len(timeline)}",
                f"Evidence sources: {len(evidence)}",
                f"Root cause: {root_cause}",
            ],
            recommended_actions=[
                {"type": "CREATE_ALERT", "target": "forensic_report", "reason": root_cause},
            ],
            data_sources_consulted=list(evidence.keys()) if evidence else ["alert_data"],
        )

    def _build_timeline(self, alert: Alert) -> list[TimelineEntry]:
        """Build a chronological timeline from alert events."""
        entries: list[TimelineEntry] = []

        sorted_events = sorted(alert.events, key=lambda e: e.timestamp)

        for event in sorted_events:
            entries.append(TimelineEntry(
                timestamp=event.timestamp,
                agent_id=self.agent_id,
                description=(
                    f"[{event.source_adapter}] {event.event_type} "
                    f"(severity: {event.severity.value})"
                ),
                evidence={
                    "event_id": event.id,
                    "mitre_attack": event.mitre_attack,
                    "affected_assets": event.affected_assets,
                    "iocs": [{"type": i.type, "value": i.value} for i in event.iocs],
                },
            ))

        return entries

    async def _collect_evidence(self, alert: Alert) -> dict[str, Any]:
        """Collect evidence from all available adapters."""
        evidence: dict[str, Any] = {
            "alert_events": len(alert.events),
            "collection_timestamp": datetime.utcnow().isoformat(),
        }

        if self._adapter_registry is None:
            return evidence

        for adapter_type in ["siem", "edr", "identity"]:
            adapters = self._adapter_registry.get_by_type(adapter_type)
            for adapter in adapters:
                try:
                    events = await adapter.safe_get_events(alert.created_at)
                    evidence[f"{adapter_type}_{adapter.vendor}"] = {
                        "event_count": len(events),
                        "adapter_health": adapter.health_state.value,
                    }
                except Exception:
                    evidence[f"{adapter_type}_{adapter.vendor}"] = {"error": "collection_failed"}

        return evidence

    async def _analyze_root_cause(
        self,
        alert: Alert,
        timeline: list[TimelineEntry],
        evidence: dict[str, Any],
    ) -> str:
        """Use LLM to analyze root cause from timeline and evidence."""
        prompt_parts = [
            "Analyze the following security incident timeline and determine the root cause.\n",
            "## Timeline\n",
        ]
        for entry in timeline[:20]:
            prompt_parts.append(f"- [{entry.timestamp.isoformat()}] {entry.description}")

        prompt_parts.append(f"\n## Evidence Sources: {list(evidence.keys())}\n")
        prompt_parts.append("\nProvide a concise root cause analysis (1-2 sentences).")

        try:
            response = await self._llm_client.messages.create(
                model=self._llm_model,
                max_tokens=512,
                messages=[{"role": "user", "content": "\n".join(prompt_parts)}],
            )
            return response.content[0].text.strip()
        except Exception:
            return "Root cause analysis failed — LLM error"
