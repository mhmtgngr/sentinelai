"""Deep forensic investigation agent."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from src.agents.base_agent import AgentCapability, AgentResult, BaseAgent
from src.core.event_bus import Event, EventBus

logger = logging.getLogger(__name__)


@dataclass
class ForensicCase:
    case_id: str = field(default_factory=lambda: str(uuid4()))
    incident_id: str = ""
    status: str = "open"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    iocs_extracted: list[dict[str, str]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ForensicAnalystAgent(BaseAgent):
    """Conducts deep forensic investigations: evidence collection, timeline reconstruction, IOC extraction."""

    name = "forensic_analyst"
    capability = AgentCapability.FORENSICS

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        super().__init__(event_bus, config)
        self._cases: dict[str, ForensicCase] = {}

    async def process(self, event: Event) -> AgentResult:
        """Initiate a forensic investigation from an incident or threat event."""
        data = event.data
        incident_id = data.get("incident_id", event.event_id)

        case = ForensicCase(incident_id=incident_id)
        self._cases[case.case_id] = case

        # Phase 1: Evidence collection
        evidence = self._collect_evidence(data)
        case.evidence.extend(evidence)

        # Phase 2: Timeline reconstruction
        timeline = self._reconstruct_timeline(data, evidence)
        case.timeline = timeline

        # Phase 3: IOC extraction
        iocs = self._extract_iocs(data, evidence)
        case.iocs_extracted = iocs

        # Phase 4: Generate findings
        findings = self._analyze_evidence(case)
        case.findings = findings

        return AgentResult(
            agent_name=self.name,
            action="investigate",
            success=True,
            data={
                "case_id": case.case_id,
                "evidence_count": len(evidence),
                "iocs_found": len(iocs),
                "findings_count": len(findings),
                "timeline_events": len(timeline),
            },
        )

    async def run_autonomous(self) -> list[AgentResult]:
        """Review open cases for additional evidence or correlations."""
        results = []
        for case in self._cases.values():
            if case.status == "open":
                # Cross-reference IOCs across cases
                cross_refs = self._cross_reference_iocs(case)
                if cross_refs:
                    case.findings.append({
                        "type": "cross_case_correlation",
                        "details": cross_refs,
                    })
                    results.append(AgentResult(
                        agent_name=self.name,
                        action="cross_reference",
                        success=True,
                        data={"case_id": case.case_id, "correlations": len(cross_refs)},
                    ))
        return results

    def _collect_evidence(self, data: dict) -> list[dict]:
        evidence = []
        # Collect network evidence
        if data.get("source_ip") or data.get("destination_ip"):
            evidence.append({
                "type": "network",
                "source_ip": data.get("source_ip"),
                "destination_ip": data.get("destination_ip"),
                "port": data.get("port"),
                "protocol": data.get("protocol"),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })
        # Collect process evidence
        if data.get("process_name") or data.get("command_line"):
            evidence.append({
                "type": "process",
                "process_name": data.get("process_name"),
                "command_line": data.get("command_line"),
                "pid": data.get("pid"),
                "parent_pid": data.get("parent_pid"),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })
        # Collect file evidence
        if data.get("file_path") or data.get("file_hash"):
            evidence.append({
                "type": "file",
                "file_path": data.get("file_path"),
                "file_hash": data.get("file_hash"),
                "file_size": data.get("file_size"),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })
        # Always collect the raw event
        evidence.append({
            "type": "raw_event",
            "data": data,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
        return evidence

    def _reconstruct_timeline(self, data: dict, evidence: list[dict]) -> list[dict]:
        timeline = []
        timestamp = data.get("timestamp", datetime.now(timezone.utc).isoformat())
        timeline.append({
            "time": timestamp,
            "event": "Initial alert",
            "details": data.get("description", ""),
        })
        for e in evidence:
            timeline.append({
                "time": e["collected_at"],
                "event": f"Evidence collected: {e['type']}",
                "details": {k: v for k, v in e.items() if k not in ("collected_at", "type")},
            })
        return sorted(timeline, key=lambda x: x["time"])

    def _extract_iocs(self, data: dict, evidence: list[dict]) -> list[dict[str, str]]:
        iocs = []
        # Extract IP IOCs
        for field_name in ("source_ip", "destination_ip"):
            ip = data.get(field_name)
            if ip and not ip.startswith(("10.", "172.16.", "192.168.", "127.")):
                iocs.append({"type": "ip", "value": ip, "context": field_name})
        # Extract domain IOCs
        for field_name in ("domain", "hostname", "url"):
            val = data.get(field_name)
            if val:
                iocs.append({"type": "domain", "value": val, "context": field_name})
        # Extract hash IOCs
        for field_name in ("file_hash", "md5", "sha256", "sha1"):
            val = data.get(field_name)
            if val:
                iocs.append({"type": "hash", "value": val, "context": field_name})
        return iocs

    def _analyze_evidence(self, case: ForensicCase) -> list[dict]:
        findings = []
        # Check for known malicious patterns in evidence
        for e in case.evidence:
            if e["type"] == "process":
                cmd = (e.get("command_line") or "").lower()
                suspicious_commands = [
                    "powershell -enc", "certutil -urlcache", "bitsadmin /transfer",
                    "mshta", "regsvr32 /s /n", "rundll32",
                ]
                for sus in suspicious_commands:
                    if sus in cmd:
                        findings.append({
                            "type": "suspicious_process",
                            "severity": "high",
                            "details": f"Suspicious command detected: {sus}",
                            "evidence": e,
                        })
        return findings

    def _cross_reference_iocs(self, case: ForensicCase) -> list[dict]:
        correlations = []
        for other_case in self._cases.values():
            if other_case.case_id == case.case_id:
                continue
            for ioc in case.iocs_extracted:
                for other_ioc in other_case.iocs_extracted:
                    if ioc["value"] == other_ioc["value"]:
                        correlations.append({
                            "ioc": ioc["value"],
                            "type": ioc["type"],
                            "related_case": other_case.case_id,
                        })
        return correlations

    def get_case(self, case_id: str) -> ForensicCase | None:
        return self._cases.get(case_id)
