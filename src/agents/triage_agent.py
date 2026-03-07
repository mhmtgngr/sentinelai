"""Triage Agent — Alert classification and prioritization.

First agent in the reactive pipeline. Classifies incoming alerts,
assigns severity, deduplicates, and routes to appropriate next agent.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from src.agents.base_agent import BaseAgent
from src.core.models import AgentDecision, Alert, Severity, Verdict
from src.memory.threat_intel import ThreatIntelCache
from src.memory.vector_store import VectorStore

logger = logging.getLogger(__name__)

TRIAGE_SYSTEM_PROMPT = """You are a security triage analyst. Analyze the following security event and provide a classification.

Respond in JSON format with these fields:
- verdict: one of TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, UNDETERMINED
- confidence: float 0.0-1.0
- severity: one of CRITICAL, HIGH, MEDIUM, LOW, INFO
- mitre_tactic: the primary MITRE ATT&CK tactic (e.g., "Initial Access", "Credential Access")
- reasoning: list of strings explaining your analysis
- recommended_actions: list of action objects with "type" and "target" fields
- escalate_to: which agent should handle next (threat_hunter, incident_responder, or none)
"""


class TriageAgent(BaseAgent):
    """Alert triage and prioritization agent.

    Classifies incoming security events using:
    1. Vector similarity search for historical context
    2. Threat intelligence enrichment
    3. LLM-based classification
    """

    def __init__(
        self,
        vector_store: VectorStore | None = None,
        threat_intel: ThreatIntelCache | None = None,
        llm_client: Any = None,
        llm_model: str = "claude-haiku-4-5-20251001",
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_id="triage", timeout_seconds=30, **kwargs)
        self._vector_store = vector_store
        self._threat_intel = threat_intel
        self._llm_client = llm_client
        self._llm_model = llm_model

    @property
    def capabilities(self) -> list[str]:
        return ["triage", "classify", "deduplicate"]

    async def process(self, alert: Alert) -> AgentDecision:
        """Classify and prioritize an alert."""
        similar_events = await self._get_similar_events(alert)
        intel_enrichment = await self._enrich_iocs(alert)
        prompt = self._build_triage_prompt(alert, similar_events, intel_enrichment)

        if self._llm_client is not None:
            response = await self._call_llm(prompt)
            return self._parse_triage_response(alert, response)

        return self._rule_based_triage(alert, intel_enrichment)

    async def _get_similar_events(self, alert: Alert) -> list[dict[str, Any]]:
        """Query vector store for similar past events."""
        if self._vector_store is None or not alert.events:
            return []

        event = alert.events[0]
        query = f"{event.event_type} {event.severity.value} {' '.join(ioc.value for ioc in event.iocs)}"
        return await self._vector_store.search_similar(query, n_results=5)

    async def _enrich_iocs(self, alert: Alert) -> list[dict[str, Any]]:
        """Enrich IOCs with threat intelligence."""
        if self._threat_intel is None:
            return []

        enrichments = []
        for event in alert.events:
            for ioc in event.iocs:
                enrichment = await self._threat_intel.enrich_ioc(ioc)
                enrichments.append(enrichment)
        return enrichments

    def _build_triage_prompt(
        self,
        alert: Alert,
        similar_events: list[dict[str, Any]],
        intel: list[dict[str, Any]],
    ) -> str:
        """Build LLM prompt for triage classification."""
        parts = [TRIAGE_SYSTEM_PROMPT, "\n## Alert Data\n"]

        for event in alert.events[:5]:
            parts.append(f"- Source: {event.source_adapter}, Type: {event.event_type}")
            parts.append(f"  Severity: {event.severity.value}, MITRE: {event.mitre_attack}")
            parts.append(f"  Assets: {event.affected_assets}")
            parts.append(f"  IOCs: {[{'type': i.type, 'value': i.value} for i in event.iocs]}")

        if similar_events:
            parts.append("\n## Similar Past Events\n")
            for se in similar_events[:3]:
                parts.append(f"- {se.get('document', 'N/A')}")

        if intel:
            parts.append("\n## Threat Intelligence\n")
            for ie in intel[:5]:
                parts.append(f"- {ie.get('ioc_value', 'N/A')}: reputation={ie.get('reputation', 'unknown')}")

        return "\n".join(parts)

    async def _call_llm(self, prompt: str) -> str:
        """Call the LLM for classification."""
        response = await self._llm_client.messages.create(
            model=self._llm_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _parse_triage_response(self, alert: Alert, response: str) -> AgentDecision:
        """Parse LLM response into AgentDecision."""
        try:
            # Extract JSON from response (handle markdown code blocks)
            text = response.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            data = json.loads(text)

            return AgentDecision(
                agent_id=self.agent_id,
                alert_id=alert.id,
                confidence=min(max(float(data.get("confidence", 0.5)), 0.0), 1.0),
                reasoning_trace=data.get("reasoning", ["LLM classification"]),
                recommended_actions=data.get("recommended_actions", []),
                data_sources_consulted=["vector_store", "threat_intel", "llm"],
                dissenting_signals=[],
            )
        except (json.JSONDecodeError, KeyError, IndexError):
            logger.warning("Failed to parse LLM triage response, falling back to rule-based")
            return self._rule_based_triage(alert, [])

    def _rule_based_triage(self, alert: Alert, intel: list[dict[str, Any]]) -> AgentDecision:
        """Fallback rule-based triage when LLM is unavailable."""
        severity_scores = {
            Severity.CRITICAL: 0.95,
            Severity.HIGH: 0.80,
            Severity.MEDIUM: 0.60,
            Severity.LOW: 0.40,
            Severity.INFO: 0.20,
        }

        max_severity = Severity.INFO
        for event in alert.events:
            if list(Severity).index(event.severity) < list(Severity).index(max_severity):
                max_severity = event.severity

        confidence = severity_scores.get(max_severity, 0.5)

        has_malicious_intel = any(
            ie.get("reputation") == "malicious" for ie in intel
        )
        if has_malicious_intel:
            confidence = min(confidence + 0.15, 1.0)

        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=confidence,
            reasoning_trace=[
                f"Rule-based triage (LLM unavailable)",
                f"Max severity: {max_severity.value}",
                f"Malicious intel match: {has_malicious_intel}",
            ],
            recommended_actions=[],
            data_sources_consulted=["sigma_rules", "threat_intel"],
        )
