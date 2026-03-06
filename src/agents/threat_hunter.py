"""Proactive threat hunting agent."""

from __future__ import annotations

import logging
from typing import Any

from src.agents.base_agent import AgentCapability, AgentResult, BaseAgent
from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)

# Threat hunting hypotheses based on MITRE ATT&CK
HUNTING_HYPOTHESES = [
    {
        "id": "TH001",
        "name": "Unusual outbound connections",
        "description": "Look for connections to rare external IPs/domains",
        "mitre": "TA0011-Command and Control",
        "indicators": ["rare_destination", "unusual_port", "high_frequency"],
    },
    {
        "id": "TH002",
        "name": "Credential dumping indicators",
        "description": "Search for LSASS access, SAM dumps, or mimikatz-like activity",
        "mitre": "TA0006-Credential Access",
        "indicators": ["lsass_access", "sam_dump", "credential_tool"],
    },
    {
        "id": "TH003",
        "name": "Living off the land binaries",
        "description": "Detect abuse of legitimate system tools (LOLBins)",
        "mitre": "TA0005-Defense Evasion",
        "indicators": ["powershell_encoded", "certutil_download", "mshta_execution"],
    },
    {
        "id": "TH004",
        "name": "DNS tunneling",
        "description": "High volume of DNS queries to a single domain with encoded subdomains",
        "mitre": "TA0010-Exfiltration",
        "indicators": ["high_dns_volume", "long_subdomain", "encoded_dns"],
    },
    {
        "id": "TH005",
        "name": "Lateral movement patterns",
        "description": "Remote service creation, PsExec-like activity, RDP from unusual sources",
        "mitre": "TA0008-Lateral Movement",
        "indicators": ["remote_service", "admin_share", "rdp_anomaly"],
    },
]


class ThreatHunterAgent(BaseAgent):
    """Proactively hunts for threats using hypothesis-driven investigation."""

    name = "threat_hunter"
    capability = AgentCapability.THREAT_HUNTING

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        super().__init__(event_bus, config)
        self._hunt_results: list[dict[str, Any]] = []
        self._ioc_watchlist: list[dict[str, str]] = []

    async def process(self, event: Event) -> AgentResult:
        """Process threat intel or anomaly events for deeper investigation."""
        data = event.data
        findings = []

        # Check against IOC watchlist
        ioc_matches = self._check_ioc_watchlist(data)
        if ioc_matches:
            findings.extend(ioc_matches)

        # Check hunting hypotheses against event data
        hypothesis_matches = self._evaluate_hypotheses(data)
        if hypothesis_matches:
            findings.extend(hypothesis_matches)

        if findings:
            await self.event_bus.publish(Event(
                event_type=EventType.THREAT_DETECTED,
                data={
                    "findings": findings,
                    "source_event": event.event_id,
                    "hunt_type": "reactive",
                },
                source=self.name,
            ))

        return AgentResult(
            agent_name=self.name,
            action="hunt_reactive",
            success=True,
            data={"findings_count": len(findings), "findings": findings},
        )

    async def run_autonomous(self) -> list[AgentResult]:
        """Run proactive threat hunts based on hypotheses."""
        results = []
        for hypothesis in HUNTING_HYPOTHESES:
            result = await self._execute_hunt(hypothesis)
            results.append(result)
            if result.data.get("threats_found", 0) > 0:
                await self.event_bus.publish(Event(
                    event_type=EventType.THREAT_DETECTED,
                    data={
                        "hypothesis": hypothesis["id"],
                        "findings": result.data.get("findings", []),
                        "hunt_type": "proactive",
                    },
                    source=self.name,
                ))
        return results

    async def _execute_hunt(self, hypothesis: dict) -> AgentResult:
        """Execute a single threat hunting hypothesis."""
        self.logger.info("Executing hunt: %s", hypothesis["name"])

        # In a real implementation, this would query adapters for relevant data
        # and apply detection logic. Here we define the framework.
        findings: list[dict] = []

        await self.event_bus.publish(Event(
            event_type=EventType.THREAT_HUNT_STARTED,
            data={"hypothesis_id": hypothesis["id"], "name": hypothesis["name"]},
            source=self.name,
        ))

        await self.event_bus.publish(Event(
            event_type=EventType.THREAT_HUNT_COMPLETED,
            data={
                "hypothesis_id": hypothesis["id"],
                "findings_count": len(findings),
            },
            source=self.name,
        ))

        return AgentResult(
            agent_name=self.name,
            action=f"hunt_{hypothesis['id']}",
            success=True,
            data={
                "hypothesis": hypothesis["id"],
                "threats_found": len(findings),
                "findings": findings,
            },
        )

    def add_ioc(self, ioc_type: str, value: str, source: str = "manual") -> None:
        """Add an indicator of compromise to the watchlist."""
        self._ioc_watchlist.append({"type": ioc_type, "value": value, "source": source})

    def _check_ioc_watchlist(self, data: dict) -> list[dict]:
        matches = []
        check_fields = {
            "ip": ["source_ip", "destination_ip", "ip"],
            "domain": ["domain", "hostname", "url"],
            "hash": ["file_hash", "md5", "sha256"],
        }
        for ioc in self._ioc_watchlist:
            fields = check_fields.get(ioc["type"], [])
            for field in fields:
                if data.get(field) == ioc["value"]:
                    matches.append({
                        "type": "ioc_match",
                        "ioc": ioc,
                        "matched_field": field,
                        "matched_value": data[field],
                    })
        return matches

    def _evaluate_hypotheses(self, data: dict) -> list[dict]:
        matches = []
        desc = (data.get("description", "") + " " + data.get("rule_name", "")).lower()
        for hypothesis in HUNTING_HYPOTHESES:
            for indicator in hypothesis["indicators"]:
                if indicator.replace("_", " ") in desc:
                    matches.append({
                        "type": "hypothesis_match",
                        "hypothesis_id": hypothesis["id"],
                        "hypothesis_name": hypothesis["name"],
                        "mitre": hypothesis["mitre"],
                        "indicator": indicator,
                    })
                    break
        return matches
