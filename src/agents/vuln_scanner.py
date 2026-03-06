"""Vulnerability assessment agent."""

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
class Vulnerability:
    vuln_id: str = field(default_factory=lambda: str(uuid4()))
    cve_id: str = ""
    title: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    affected_asset: str = ""
    description: str = ""
    remediation: str = ""
    status: str = "open"
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Common vulnerability check definitions
VULN_CHECKS = [
    {
        "id": "VS-001",
        "name": "Outdated SSL/TLS versions",
        "description": "Check for SSLv3, TLS 1.0, TLS 1.1 in use",
        "severity": "high",
        "remediation": "Upgrade to TLS 1.2 or TLS 1.3",
    },
    {
        "id": "VS-002",
        "name": "Default credentials",
        "description": "Check for services using default usernames and passwords",
        "severity": "critical",
        "remediation": "Change all default credentials immediately",
    },
    {
        "id": "VS-003",
        "name": "Open management ports",
        "description": "Check for exposed RDP (3389), SSH (22), telnet (23) to public",
        "severity": "high",
        "remediation": "Restrict management ports to bastion hosts or VPN",
    },
    {
        "id": "VS-004",
        "name": "Missing security patches",
        "description": "Check for known CVEs with available patches",
        "severity": "high",
        "remediation": "Apply vendor patches per patch management policy",
    },
    {
        "id": "VS-005",
        "name": "Weak authentication",
        "description": "Check for services without MFA or with weak password policies",
        "severity": "medium",
        "remediation": "Enable MFA and enforce strong password policies",
    },
    {
        "id": "VS-006",
        "name": "Misconfigured CORS",
        "description": "Check for overly permissive CORS headers on web services",
        "severity": "medium",
        "remediation": "Restrict CORS to specific trusted origins",
    },
    {
        "id": "VS-007",
        "name": "Exposed sensitive endpoints",
        "description": "Check for exposed admin panels, debug endpoints, API docs",
        "severity": "high",
        "remediation": "Restrict access or disable debug endpoints in production",
    },
]


class VulnScannerAgent(BaseAgent):
    """Scans for vulnerabilities across connected security products and assets."""

    name = "vuln_scanner"
    capability = AgentCapability.VULNERABILITY_SCAN

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        super().__init__(event_bus, config)
        self._vulnerabilities: dict[str, Vulnerability] = {}
        self._scan_history: list[dict[str, Any]] = []

    async def process(self, event: Event) -> AgentResult:
        """Process a scan request or CVE advisory event."""
        data = event.data
        scan_type = data.get("scan_type", "targeted")

        if scan_type == "cve_advisory":
            return await self._check_cve_advisory(data)

        vulns_found = await self._run_targeted_scan(data)

        return AgentResult(
            agent_name=self.name,
            action="scan",
            success=True,
            data={
                "scan_type": scan_type,
                "vulnerabilities_found": len(vulns_found),
                "critical": sum(1 for v in vulns_found if v.severity == "critical"),
                "high": sum(1 for v in vulns_found if v.severity == "high"),
            },
        )

    async def run_autonomous(self) -> list[AgentResult]:
        """Run periodic vulnerability assessments."""
        results = []
        all_vulns: list[Vulnerability] = []

        for check in VULN_CHECKS:
            vulns = self._execute_check(check)
            all_vulns.extend(vulns)

        for vuln in all_vulns:
            self._vulnerabilities[vuln.vuln_id] = vuln
            if vuln.severity in ("critical", "high"):
                await self.event_bus.publish(Event(
                    event_type=EventType.ALERT_RECEIVED,
                    data={
                        "type": "vulnerability",
                        "vuln_id": vuln.vuln_id,
                        "cve_id": vuln.cve_id,
                        "severity": vuln.severity,
                        "title": vuln.title,
                        "affected_asset": vuln.affected_asset,
                    },
                    source=self.name,
                ))

        self._scan_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks_run": len(VULN_CHECKS),
            "vulns_found": len(all_vulns),
        })

        results.append(AgentResult(
            agent_name=self.name,
            action="periodic_scan",
            success=True,
            data={
                "checks_run": len(VULN_CHECKS),
                "vulnerabilities_found": len(all_vulns),
            },
        ))
        return results

    async def _run_targeted_scan(self, data: dict) -> list[Vulnerability]:
        """Run a targeted scan against a specific asset or check."""
        target = data.get("target", "")
        vulns = []
        for check in VULN_CHECKS:
            found = self._execute_check(check, target=target)
            vulns.extend(found)
        return vulns

    async def _check_cve_advisory(self, data: dict) -> AgentResult:
        """Check if a newly published CVE affects our environment."""
        cve_id = data.get("cve_id", "")
        affected_products = data.get("affected_products", [])

        # In production, this would query asset inventory and patch management
        return AgentResult(
            agent_name=self.name,
            action="cve_check",
            success=True,
            data={
                "cve_id": cve_id,
                "affected_products": affected_products,
                "assets_at_risk": 0,
            },
        )

    def _execute_check(self, check: dict, target: str = "") -> list[Vulnerability]:
        """Execute a vulnerability check. In production, queries real systems."""
        # Framework placeholder — real implementation queries adapters
        return []

    def get_vulnerability_report(self) -> dict[str, Any]:
        vulns = list(self._vulnerabilities.values())
        return {
            "total": len(vulns),
            "by_severity": {
                "critical": sum(1 for v in vulns if v.severity == "critical"),
                "high": sum(1 for v in vulns if v.severity == "high"),
                "medium": sum(1 for v in vulns if v.severity == "medium"),
                "low": sum(1 for v in vulns if v.severity == "low"),
            },
            "open": sum(1 for v in vulns if v.status == "open"),
            "remediated": sum(1 for v in vulns if v.status == "remediated"),
            "scan_history": self._scan_history[-10:],
        }
