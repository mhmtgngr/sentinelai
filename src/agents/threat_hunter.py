"""Threat Hunter Agent — Proactive threat hunting and correlation.

Enriches alerts with threat intel, correlates across data sources,
and maps to MITRE ATT&CK framework.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from src.agents.base_agent import BaseAgent
from src.core.models import AgentDecision, Alert

logger = logging.getLogger(__name__)

HUNT_SYSTEM_PROMPT = """You are a threat hunter analyzing security data for indicators of compromise.

Correlate the provided evidence across multiple data sources. Map findings to MITRE ATT&CK techniques.

Respond in JSON format:
- confidence: float 0.0-1.0
- threat_confirmed: boolean
- attack_chain: list of MITRE ATT&CK technique IDs with descriptions
- iocs_found: list of IOC objects with type, value, and context
- lateral_movement_detected: boolean
- reasoning: list of analysis steps
- recommended_actions: list of action objects with "type" and "target"
"""


class ThreatHunterAgent(BaseAgent):
    """Proactive threat hunting and correlation agent.

    Enriches alerts by:
    1. Querying SIEM and EDR adapters for correlated events
    2. Enriching IOCs with threat intelligence
    3. Using LLM for ATT&CK chain analysis
    """

    def __init__(
        self,
        adapter_registry: Any = None,
        threat_intel: Any = None,
        llm_client: Any = None,
        llm_model: str = "claude-sonnet-4-6",
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_id="threat_hunter", timeout_seconds=120, **kwargs)
        self._adapter_registry = adapter_registry
        self._threat_intel = threat_intel
        self._llm_client = llm_client
        self._llm_model = llm_model

    @property
    def capabilities(self) -> list[str]:
        return ["hunt", "correlate", "enrich"]

    async def process(self, alert: Alert) -> AgentDecision:
        """Hunt for additional evidence and correlate findings."""
        correlated_data = await self._correlate_across_sources(alert)
        enriched_iocs = await self._enrich_all_iocs(alert)

        prompt = self._build_hunt_prompt(alert, correlated_data, enriched_iocs)

        if self._llm_client is not None:
            response = await self._call_llm(prompt)
            return self._parse_hunt_response(alert, response)

        return self._rule_based_hunt(alert, correlated_data, enriched_iocs)

    async def _correlate_across_sources(self, alert: Alert) -> dict[str, Any]:
        """Query SIEM and EDR for correlated events."""
        correlated: dict[str, Any] = {"siem": [], "edr": []}

        if self._adapter_registry is None:
            return correlated

        for adapter in self._adapter_registry.get_by_type("siem"):
            try:
                events = await adapter.safe_get_events(alert.created_at)
                correlated["siem"].extend(
                    e for e in events
                    if any(ioc.value in str(e.raw_payload) for ev in alert.events for ioc in ev.iocs)
                )
            except Exception:
                logger.exception("SIEM correlation failed")

        for adapter in self._adapter_registry.get_by_type("edr"):
            try:
                events = await adapter.safe_get_events(alert.created_at)
                correlated["edr"].extend(
                    e for e in events
                    if any(asset in e.affected_assets for ev in alert.events for asset in ev.affected_assets)
                )
            except Exception:
                logger.exception("EDR correlation failed")

        return correlated

    async def _enrich_all_iocs(self, alert: Alert) -> list[dict[str, Any]]:
        """Enrich all IOCs from the alert."""
        if self._threat_intel is None:
            return []

        enrichments = []
        for event in alert.events:
            for ioc in event.iocs:
                enrichment = await self._threat_intel.enrich_ioc(ioc)
                enrichments.append(enrichment)
        return enrichments

    def _build_hunt_prompt(
        self,
        alert: Alert,
        correlated: dict[str, Any],
        intel: list[dict[str, Any]],
    ) -> str:
        """Build LLM prompt for threat hunting analysis."""
        parts = [HUNT_SYSTEM_PROMPT, "\n## Alert Context\n"]

        for event in alert.events[:5]:
            parts.append(f"- Type: {event.event_type}, Severity: {event.severity.value}")
            parts.append(f"  MITRE: {event.mitre_attack}")
            parts.append(f"  IOCs: {[{'type': i.type, 'value': i.value} for i in event.iocs]}")

        if correlated["siem"]:
            parts.append(f"\n## Correlated SIEM Events: {len(correlated['siem'])} found\n")

        if correlated["edr"]:
            parts.append(f"\n## Correlated EDR Events: {len(correlated['edr'])} found\n")

        if intel:
            parts.append("\n## Threat Intelligence\n")
            for ie in intel[:5]:
                parts.append(f"- {ie.get('ioc_value')}: {ie.get('reputation', 'unknown')}")

        return "\n".join(parts)

    async def _call_llm(self, prompt: str) -> str:
        response = await self._llm_client.messages.create(
            model=self._llm_model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _parse_hunt_response(self, alert: Alert, response: str) -> AgentDecision:
        try:
            text = response.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            data = json.loads(text)

            return AgentDecision(
                agent_id=self.agent_id,
                alert_id=alert.id,
                confidence=min(max(float(data.get("confidence", 0.5)), 0.0), 1.0),
                reasoning_trace=data.get("reasoning", []),
                recommended_actions=data.get("recommended_actions", []),
                data_sources_consulted=["siem", "edr", "threat_intel", "llm"],
            )
        except (json.JSONDecodeError, KeyError):
            return self._rule_based_hunt(alert, {}, [])

    def _rule_based_hunt(
        self,
        alert: Alert,
        correlated: dict[str, Any],
        intel: list[dict[str, Any]],
    ) -> AgentDecision:
        """Fallback when LLM is unavailable."""
        has_correlated = bool(correlated.get("siem") or correlated.get("edr"))
        has_malicious = any(ie.get("reputation") == "malicious" for ie in intel)

        confidence = 0.5
        if has_correlated:
            confidence += 0.2
        if has_malicious:
            confidence += 0.2

        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=min(confidence, 1.0),
            reasoning_trace=[
                "Rule-based hunt (LLM unavailable)",
                f"Correlated events found: {has_correlated}",
                f"Malicious intel match: {has_malicious}",
            ],
            data_sources_consulted=["siem", "edr", "threat_intel"],
        )

    async def proactive_hunt(self, hypothesis: str) -> AgentDecision:
        """Run a proactive threat hunt based on a hypothesis."""
        alert = Alert()
        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=0.0,
            reasoning_trace=[f"Proactive hunt: {hypothesis}", "No implementation yet"],
            data_sources_consulted=[],
        )
