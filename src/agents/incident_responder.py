"""Incident Responder Agent — Automated incident response.

Selects and executes response playbooks based on threat assessment.
Validates actions against confidence thresholds and blast radius limits.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from src.agents.base_agent import BaseAgent
from src.core.models import (
    ActionResult,
    ActionStatus,
    ActionType,
    AgentDecision,
    Alert,
)

logger = logging.getLogger(__name__)

RESPOND_SYSTEM_PROMPT = """You are an incident responder. Based on the threat assessment, determine the appropriate response actions.

Consider:
- Severity and confidence of the threat
- Blast radius of proposed actions
- Available rollback procedures
- Whether human approval is required

Respond in JSON format:
- confidence: float 0.0-1.0
- actions: list of objects with "type" (BLOCK_IP, DISABLE_ACCOUNT, ISOLATE_HOST, FORCE_PASSWORD_RESET, QUARANTINE_FILE, ADD_TO_WATCHLIST), "target", "reason", "rollback_procedure"
- requires_human_approval: boolean
- reasoning: list of analysis steps
"""


class IncidentResponderAgent(BaseAgent):
    """Automated incident response agent.

    Selects playbooks, refines actions with LLM context,
    and validates against safety controls before execution.
    """

    def __init__(
        self,
        playbook_dir: Path | str = "config/playbooks",
        llm_client: Any = None,
        llm_model: str = "claude-sonnet-4-6",
        max_blast_radius: int = 5,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_id="incident_responder", timeout_seconds=60, confidence_threshold=0.85, **kwargs)
        self._playbook_dir = Path(playbook_dir)
        self._llm_client = llm_client
        self._llm_model = llm_model
        self._max_blast_radius = max_blast_radius

    @property
    def capabilities(self) -> list[str]:
        return ["respond", "remediate", "rollback"]

    async def process(self, alert: Alert) -> AgentDecision:
        """Determine and validate response actions for an alert."""
        playbook = self._select_playbook(alert)

        if self._llm_client is not None:
            prompt = self._build_response_prompt(alert, playbook)
            response = await self._call_llm(prompt)
            decision = self._parse_response(alert, response)
        else:
            decision = self._rule_based_response(alert, playbook)

        decision.recommended_actions = self._validate_actions(decision.recommended_actions)
        return decision

    def _select_playbook(self, alert: Alert) -> dict[str, Any]:
        """Select the appropriate response playbook based on alert type."""
        if not self._playbook_dir.exists():
            return {}

        best_match: dict[str, Any] = {}
        event_types = {e.event_type for e in alert.events}
        mitre_techniques: set[str] = set()
        for event in alert.events:
            mitre_techniques.update(event.mitre_attack)

        for playbook_file in self._playbook_dir.glob("*.yml"):
            try:
                with open(playbook_file) as f:
                    playbook = yaml.safe_load(f) or {}
                triggers = playbook.get("triggers", [])
                for trigger in triggers:
                    if trigger.get("alert_type") in event_types:
                        return playbook
                    if trigger.get("sigma_rule") in mitre_techniques:
                        best_match = playbook
            except Exception:
                continue

        return best_match

    def _build_response_prompt(self, alert: Alert, playbook: dict[str, Any]) -> str:
        parts = [RESPOND_SYSTEM_PROMPT, "\n## Threat Assessment\n"]

        for event in alert.events[:5]:
            parts.append(f"- Type: {event.event_type}, Severity: {event.severity.value}")
            parts.append(f"  Assets: {event.affected_assets}")
            parts.append(f"  IOCs: {[i.value for i in event.iocs]}")

        if playbook:
            parts.append(f"\n## Selected Playbook: {playbook.get('name', 'unknown')}\n")
            for step in playbook.get("steps", [])[:5]:
                parts.append(f"- {step.get('name', 'step')}: {step.get('action', 'N/A')}")

        parts.append(f"\n## Safety Constraints\n")
        parts.append(f"- Max blast radius: {self._max_blast_radius} assets")
        parts.append(f"- Confidence threshold: {self.confidence_threshold}")

        return "\n".join(parts)

    async def _call_llm(self, prompt: str) -> str:
        response = await self._llm_client.messages.create(
            model=self._llm_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _parse_response(self, alert: Alert, response: str) -> AgentDecision:
        try:
            text = response.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            data = json.loads(text)

            actions = []
            for action in data.get("actions", []):
                actions.append({
                    "type": action.get("type", "ADD_TO_WATCHLIST"),
                    "target": action.get("target", ""),
                    "reason": action.get("reason", ""),
                    "rollback_procedure": action.get("rollback_procedure", ""),
                })

            return AgentDecision(
                agent_id=self.agent_id,
                alert_id=alert.id,
                confidence=min(max(float(data.get("confidence", 0.5)), 0.0), 1.0),
                reasoning_trace=data.get("reasoning", []),
                recommended_actions=actions,
                data_sources_consulted=["playbook", "llm"],
            )
        except (json.JSONDecodeError, KeyError):
            return self._rule_based_response(alert, {})

    def _rule_based_response(self, alert: Alert, playbook: dict[str, Any]) -> AgentDecision:
        """Fallback response when LLM is unavailable."""
        actions = []
        for event in alert.events:
            for ioc in event.iocs:
                if ioc.type == "ip":
                    actions.append({
                        "type": "BLOCK_IP",
                        "target": ioc.value,
                        "reason": f"IOC from {event.event_type}",
                        "rollback_procedure": f"Unblock IP {ioc.value}",
                    })

        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=0.6,
            reasoning_trace=["Rule-based response (LLM unavailable)"],
            recommended_actions=actions[:self._max_blast_radius],
            data_sources_consulted=["sigma_rules"],
        )

    def _validate_actions(self, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate actions against blast radius and safety constraints."""
        if len(actions) > self._max_blast_radius:
            logger.warning(
                "Actions exceed blast radius limit (%d > %d), truncating",
                len(actions), self._max_blast_radius,
            )
            actions = actions[:self._max_blast_radius]

        valid_types = {at.value for at in ActionType}
        validated = []
        for action in actions:
            if action.get("type") in valid_types:
                validated.append(action)
            else:
                logger.warning("Invalid action type '%s' rejected", action.get("type"))

        return validated
