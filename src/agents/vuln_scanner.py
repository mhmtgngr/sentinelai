"""Vulnerability Scanner Agent — Periodic vulnerability assessment.

Scans registered assets for known vulnerabilities,
cross-references with MITRE ATT&CK, and assesses exploitability.
"""

from __future__ import annotations

import logging
from typing import Any

from src.agents.base_agent import BaseAgent
from src.core.models import AgentDecision, Alert, Severity

logger = logging.getLogger(__name__)

KNOWN_VULN_PATTERNS = {
    "ssh": {
        "cves": ["CVE-2023-38408", "CVE-2023-48795"],
        "mitre": ["T1021.004"],
        "severity": Severity.HIGH,
    },
    "http": {
        "cves": ["CVE-2024-23897", "CVE-2023-44487"],
        "mitre": ["T1190"],
        "severity": Severity.CRITICAL,
    },
    "smb": {
        "cves": ["CVE-2020-0796", "CVE-2017-0144"],
        "mitre": ["T1021.002", "T1210"],
        "severity": Severity.CRITICAL,
    },
    "rdp": {
        "cves": ["CVE-2019-0708"],
        "mitre": ["T1021.001"],
        "severity": Severity.CRITICAL,
    },
}


class VulnScannerAgent(BaseAgent):
    """Vulnerability assessment agent.

    Identifies vulnerabilities in affected assets by cross-referencing
    with known vulnerability databases and MITRE ATT&CK.
    """

    def __init__(
        self,
        llm_client: Any = None,
        llm_model: str = "claude-haiku-4-5-20251001",
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_id="vuln_scanner", timeout_seconds=600, confidence_threshold=0.70, **kwargs)
        self._llm_client = llm_client
        self._llm_model = llm_model

    @property
    def capabilities(self) -> list[str]:
        return ["scan", "assess_vulnerability"]

    async def process(self, alert: Alert) -> AgentDecision:
        """Assess vulnerabilities related to an alert."""
        vuln_findings = self._check_known_vulns(alert)

        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=0.75 if vuln_findings else 0.50,
            reasoning_trace=[
                f"Checked {len(KNOWN_VULN_PATTERNS)} vulnerability patterns",
                f"Findings: {len(vuln_findings)} potential vulnerabilities",
                *[f"  - {f['service']}: {f['cves']}" for f in vuln_findings],
            ],
            recommended_actions=[
                {
                    "type": "ADD_TO_WATCHLIST",
                    "target": finding["service"],
                    "reason": f"Potential vulnerability: {finding['cves']}",
                }
                for finding in vuln_findings
            ],
            data_sources_consulted=["known_vuln_db", "mitre_attack"],
        )

    def _check_known_vulns(self, alert: Alert) -> list[dict[str, Any]]:
        """Check alert data against known vulnerability patterns."""
        findings: list[dict[str, Any]] = []

        all_text = " ".join(
            f"{e.event_type} {str(e.normalized)} {str(e.raw_payload)}"
            for e in alert.events
        ).lower()

        for service, vuln_info in KNOWN_VULN_PATTERNS.items():
            if service in all_text:
                findings.append({
                    "service": service,
                    "cves": vuln_info["cves"],
                    "mitre": vuln_info["mitre"],
                    "severity": vuln_info["severity"].value,
                })

        mitre_in_alert: set[str] = set()
        for event in alert.events:
            mitre_in_alert.update(event.mitre_attack)

        for service, vuln_info in KNOWN_VULN_PATTERNS.items():
            if mitre_in_alert & set(vuln_info["mitre"]):
                if not any(f["service"] == service for f in findings):
                    findings.append({
                        "service": service,
                        "cves": vuln_info["cves"],
                        "mitre": vuln_info["mitre"],
                        "severity": vuln_info["severity"].value,
                        "matched_by": "mitre_technique",
                    })

        return findings

    async def scheduled_scan(self, asset_list: list[str] | None = None) -> AgentDecision:
        """Run a periodic vulnerability scan across known assets."""
        assets = asset_list or []

        return AgentDecision(
            agent_id=self.agent_id,
            confidence=0.70,
            reasoning_trace=[
                "Scheduled vulnerability scan",
                f"Assets scanned: {len(assets)}",
                "No active scanning implemented — using pattern matching only",
            ],
            data_sources_consulted=["known_vuln_db"],
        )
