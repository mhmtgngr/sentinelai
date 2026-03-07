"""Tests for concrete agent implementations."""

from __future__ import annotations

import pytest

from src.core.models import AgentDecision, Alert, SecurityEvent, Severity


def _make_alert(severity: Severity = Severity.HIGH) -> Alert:
    event = SecurityEvent(
        source_adapter="siem",
        event_type="authentication_failure",
        severity=severity,
        raw_payload={"src_ip": "10.0.0.1", "count": 50},
    )
    return Alert(events=[event])


class TestTriageAgent:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.agents.triage_agent import TriageAgent
        assert TriageAgent is not None

    @pytest.mark.asyncio
    async def test_capabilities(self):
        from src.agents.triage_agent import TriageAgent
        agent = TriageAgent()
        assert "triage" in agent.capabilities
        assert "classify" in agent.capabilities

    @pytest.mark.asyncio
    async def test_rule_based_fallback(self):
        from src.agents.triage_agent import TriageAgent
        agent = TriageAgent()
        alert = _make_alert(severity=Severity.CRITICAL)
        decision = await agent.execute(alert)
        assert isinstance(decision, AgentDecision)
        assert decision.confidence > 0

    @pytest.mark.asyncio
    async def test_agent_id(self):
        from src.agents.triage_agent import TriageAgent
        agent = TriageAgent()
        assert agent.agent_id == "triage"


class TestThreatHunter:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.agents.threat_hunter import ThreatHunterAgent
        assert ThreatHunterAgent is not None

    @pytest.mark.asyncio
    async def test_capabilities(self):
        from src.agents.threat_hunter import ThreatHunterAgent
        agent = ThreatHunterAgent()
        assert "hunt" in agent.capabilities
        assert "correlate" in agent.capabilities

    @pytest.mark.asyncio
    async def test_process(self):
        from src.agents.threat_hunter import ThreatHunterAgent
        agent = ThreatHunterAgent()
        alert = _make_alert()
        decision = await agent.execute(alert)
        assert isinstance(decision, AgentDecision)


class TestIncidentResponder:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.agents.incident_responder import IncidentResponderAgent
        assert IncidentResponderAgent is not None

    @pytest.mark.asyncio
    async def test_capabilities(self):
        from src.agents.incident_responder import IncidentResponderAgent
        agent = IncidentResponderAgent()
        assert "respond" in agent.capabilities

    @pytest.mark.asyncio
    async def test_process(self):
        from src.agents.incident_responder import IncidentResponderAgent
        agent = IncidentResponderAgent()
        alert = _make_alert()
        decision = await agent.execute(alert)
        assert isinstance(decision, AgentDecision)


class TestComplianceAuditor:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.agents.compliance_auditor import ComplianceAuditorAgent
        assert ComplianceAuditorAgent is not None

    @pytest.mark.asyncio
    async def test_capabilities(self):
        from src.agents.compliance_auditor import ComplianceAuditorAgent
        agent = ComplianceAuditorAgent()
        assert "audit" in agent.capabilities


class TestForensicAnalyst:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.agents.forensic_analyst import ForensicAnalystAgent
        assert ForensicAnalystAgent is not None

    @pytest.mark.asyncio
    async def test_capabilities(self):
        from src.agents.forensic_analyst import ForensicAnalystAgent
        agent = ForensicAnalystAgent()
        assert "investigate" in agent.capabilities


class TestVulnScanner:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.agents.vuln_scanner import VulnScannerAgent
        assert VulnScannerAgent is not None

    @pytest.mark.asyncio
    async def test_capabilities(self):
        from src.agents.vuln_scanner import VulnScannerAgent
        agent = VulnScannerAgent()
        assert "scan" in agent.capabilities
