"""Continuous compliance checking agent."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.agents.base_agent import AgentCapability, AgentResult, BaseAgent
from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


@dataclass
class ComplianceCheck:
    check_id: str
    framework: str
    control: str
    description: str
    severity: str = "medium"
    check_fn_name: str = ""


@dataclass
class ComplianceResult:
    check: ComplianceCheck
    passed: bool
    details: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Built-in compliance checks mapped to common frameworks
COMPLIANCE_CHECKS: list[ComplianceCheck] = [
    ComplianceCheck("CIS-001", "CIS", "5.1", "Ensure MFA is enabled for all admin accounts", "critical", "check_mfa_admin"),
    ComplianceCheck("CIS-002", "CIS", "6.2", "Ensure SSH Protocol is set to 2", "high", "check_ssh_protocol"),
    ComplianceCheck("CIS-003", "CIS", "4.1", "Ensure audit logging is enabled", "high", "check_audit_logging"),
    ComplianceCheck("SOC2-001", "SOC2", "CC6.1", "Logical access controls are in place", "critical", "check_access_controls"),
    ComplianceCheck("SOC2-002", "SOC2", "CC7.2", "Security events are monitored", "high", "check_monitoring"),
    ComplianceCheck("GDPR-001", "GDPR", "Art.32", "Encryption of personal data at rest", "critical", "check_encryption"),
    ComplianceCheck("GDPR-002", "GDPR", "Art.33", "Breach notification within 72 hours", "critical", "check_breach_notification"),
    ComplianceCheck("PCI-001", "PCI-DSS", "Req.10", "Track and monitor all access to network resources", "critical", "check_network_monitoring"),
]


class ComplianceAuditorAgent(BaseAgent):
    """Continuously audits compliance against CIS, SOC2, GDPR, and PCI-DSS frameworks."""

    name = "compliance_auditor"
    capability = AgentCapability.COMPLIANCE

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        super().__init__(event_bus, config)
        self._last_results: list[ComplianceResult] = []
        self._check_registry: dict[str, ComplianceCheck] = {c.check_id: c for c in COMPLIANCE_CHECKS}

    async def process(self, event: Event) -> AgentResult:
        """Process configuration change events to re-evaluate compliance."""
        data = event.data
        affected_checks = self._find_affected_checks(data)
        results = []

        for check in affected_checks:
            passed = self._evaluate_check(check, data)
            result = ComplianceResult(check=check, passed=passed, details=str(data))
            results.append(result)

            if not passed:
                await self.event_bus.publish(Event(
                    event_type=EventType.ALERT_RECEIVED,
                    data={
                        "type": "compliance_violation",
                        "check_id": check.check_id,
                        "framework": check.framework,
                        "control": check.control,
                        "severity": check.severity,
                        "description": check.description,
                    },
                    source=self.name,
                ))

        return AgentResult(
            agent_name=self.name,
            action="compliance_check",
            success=True,
            data={
                "checks_run": len(results),
                "passed": sum(1 for r in results if r.passed),
                "failed": sum(1 for r in results if not r.passed),
            },
        )

    async def run_autonomous(self) -> list[AgentResult]:
        """Run all compliance checks periodically."""
        results: list[ComplianceResult] = []

        for check in COMPLIANCE_CHECKS:
            passed = self._evaluate_check(check, {})
            results.append(ComplianceResult(check=check, passed=passed))

        self._last_results = results
        failed = [r for r in results if not r.passed]

        return [AgentResult(
            agent_name=self.name,
            action="full_audit",
            success=True,
            data={
                "total_checks": len(results),
                "passed": len(results) - len(failed),
                "failed": len(failed),
                "violations": [
                    {
                        "check_id": r.check.check_id,
                        "framework": r.check.framework,
                        "control": r.check.control,
                        "severity": r.check.severity,
                    }
                    for r in failed
                ],
            },
        )]

    def _find_affected_checks(self, data: dict) -> list[ComplianceCheck]:
        """Determine which compliance checks are relevant to a change event."""
        change_type = data.get("change_type", "")
        affected = []
        mapping = {
            "authentication": ["CIS-001", "SOC2-001"],
            "ssh": ["CIS-002"],
            "logging": ["CIS-003", "PCI-001", "SOC2-002"],
            "encryption": ["GDPR-001"],
            "access_control": ["SOC2-001"],
            "monitoring": ["SOC2-002", "PCI-001"],
        }
        for keyword, check_ids in mapping.items():
            if keyword in change_type.lower():
                for cid in check_ids:
                    if cid in self._check_registry:
                        affected.append(self._check_registry[cid])
        return affected or list(self._check_registry.values())

    def _evaluate_check(self, check: ComplianceCheck, context: dict) -> bool:
        """Evaluate a single compliance check. In production, queries adapters for real state."""
        # Framework for check evaluation - returns True (pass) by default.
        # Real implementation would query security product APIs.
        return True

    def get_compliance_report(self, framework: str | None = None) -> dict[str, Any]:
        """Generate a compliance report from last audit results."""
        results = self._last_results
        if framework:
            results = [r for r in results if r.check.framework == framework]

        passed = sum(1 for r in results if r.passed)
        total = len(results)

        return {
            "framework": framework or "all",
            "total_checks": total,
            "passed": passed,
            "failed": total - passed,
            "compliance_score": (passed / total * 100) if total > 0 else 0,
            "details": [
                {
                    "check_id": r.check.check_id,
                    "control": r.check.control,
                    "description": r.check.description,
                    "passed": r.passed,
                }
                for r in results
            ],
        }
