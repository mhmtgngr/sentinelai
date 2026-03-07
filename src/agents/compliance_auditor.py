"""Compliance Auditor Agent — Regulatory compliance checking.

Assesses security events and response actions for regulatory
implications (GDPR, HIPAA, PCI-DSS, SOX).
"""

from __future__ import annotations

import logging
from typing import Any

from src.agents.base_agent import BaseAgent
from src.core.models import AgentDecision, Alert

logger = logging.getLogger(__name__)

COMPLIANCE_FRAMEWORKS = {
    "gdpr": {
        "name": "GDPR",
        "data_types": ["personal_data", "email", "user", "pii"],
        "notification_required": True,
        "notification_window_hours": 72,
    },
    "hipaa": {
        "name": "HIPAA",
        "data_types": ["phi", "medical", "health", "patient"],
        "notification_required": True,
        "notification_window_hours": 60 * 24,  # 60 days
    },
    "pci_dss": {
        "name": "PCI-DSS",
        "data_types": ["credit_card", "payment", "cardholder", "pan"],
        "notification_required": True,
        "notification_window_hours": 24,
    },
}


class ComplianceAuditorAgent(BaseAgent):
    """Compliance assessment agent.

    Evaluates alerts and response actions for regulatory implications.
    """

    def __init__(
        self,
        frameworks: list[str] | None = None,
        llm_client: Any = None,
        llm_model: str = "claude-haiku-4-5-20251001",
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_id="compliance_auditor", timeout_seconds=180, confidence_threshold=0.70, **kwargs)
        self._active_frameworks = frameworks or list(COMPLIANCE_FRAMEWORKS.keys())
        self._llm_client = llm_client
        self._llm_model = llm_model

    @property
    def capabilities(self) -> list[str]:
        return ["audit", "compliance_check", "report"]

    async def process(self, alert: Alert) -> AgentDecision:
        """Assess compliance implications of an alert."""
        applicable_frameworks = self._identify_frameworks(alert)
        compliance_issues = self._check_compliance(alert, applicable_frameworks)

        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=0.85 if compliance_issues else 0.90,
            reasoning_trace=[
                f"Checked frameworks: {[f['name'] for f in applicable_frameworks]}",
                f"Issues found: {len(compliance_issues)}",
                *[f"Issue: {issue}" for issue in compliance_issues],
            ],
            recommended_actions=[
                {"type": "CREATE_ALERT", "target": "compliance_team", "reason": issue}
                for issue in compliance_issues
            ],
            data_sources_consulted=["compliance_rules", "alert_data"],
        )

    def _identify_frameworks(self, alert: Alert) -> list[dict[str, Any]]:
        """Identify which compliance frameworks apply to this alert."""
        applicable = []
        all_text = " ".join(
            str(e.raw_payload) + " " + str(e.normalized)
            for e in alert.events
        ).lower()

        for framework_id in self._active_frameworks:
            framework = COMPLIANCE_FRAMEWORKS.get(framework_id)
            if framework is None:
                continue
            for data_type in framework["data_types"]:
                if data_type in all_text:
                    applicable.append(framework)
                    break

        return applicable

    def _check_compliance(self, alert: Alert, frameworks: list[dict[str, Any]]) -> list[str]:
        """Check for compliance violations."""
        issues = []
        for framework in frameworks:
            if framework.get("notification_required"):
                window = framework.get("notification_window_hours", 72)
                issues.append(
                    f"{framework['name']}: Data breach notification may be required "
                    f"within {window} hours"
                )

        has_data_exfil = any(
            "exfiltration" in e.event_type.lower() or "data_leak" in e.event_type.lower()
            for e in alert.events
        )
        if has_data_exfil and frameworks:
            issues.append("Potential data exfiltration detected — regulatory notification likely required")

        return issues

    async def scheduled_audit(self, adapter_registry: Any = None) -> AgentDecision:
        """Run a scheduled compliance configuration audit."""
        findings: list[str] = []

        if adapter_registry:
            health = await adapter_registry.health_check_all()
            for adapter_id, status in health.items():
                if status.state.value != "HEALTHY":
                    findings.append(f"Adapter '{adapter_id}' is {status.state.value} — may affect compliance monitoring")

        return AgentDecision(
            agent_id=self.agent_id,
            confidence=0.90,
            reasoning_trace=[
                "Scheduled compliance audit",
                f"Findings: {len(findings)}",
                *findings,
            ],
            data_sources_consulted=["adapter_health", "compliance_rules"],
        )
