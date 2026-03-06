"""Tests for Sentinel-AI agents."""

import pytest
from src.core.event_bus import EventBus, Event, EventType
from src.agents.triage_agent import TriageAgent
from src.agents.threat_hunter import ThreatHunterAgent
from src.agents.incident_responder import IncidentResponderAgent
from src.agents.compliance_auditor import ComplianceAuditorAgent
from src.agents.forensic_analyst import ForensicAnalystAgent
from src.agents.vuln_scanner import VulnScannerAgent


@pytest.fixture
def event_bus():
    return EventBus()


# --- Triage Agent ---

@pytest.mark.asyncio
async def test_triage_scores_alert(event_bus):
    agent = TriageAgent(event_bus)
    await agent.initialize()

    event = Event(
        event_type=EventType.ALERT_RECEIVED,
        data={
            "severity": "high",
            "description": "Multiple failed login attempts detected",
            "source_ip": "10.0.0.1",
            "rule_id": "R001",
        },
    )
    result = await agent.process(event)

    assert result.success
    assert result.data["severity_score"] >= 75
    assert result.data["attack_type"] == "brute_force"
    assert len(result.data["mitre_tactics"]) > 0


@pytest.mark.asyncio
async def test_triage_deduplication(event_bus):
    agent = TriageAgent(event_bus)
    await agent.initialize()

    event_data = {
        "severity": "medium",
        "description": "Port scan detected",
        "source_ip": "192.168.1.100",
        "rule_id": "R002",
    }
    event1 = Event(event_type=EventType.ALERT_RECEIVED, data=event_data)
    event2 = Event(event_type=EventType.ALERT_RECEIVED, data=event_data)

    result1 = await agent.process(event1)
    result2 = await agent.process(event2)

    assert result1.action == "triage"
    assert result2.action == "deduplicate"


@pytest.mark.asyncio
async def test_triage_false_positive(event_bus):
    agent = TriageAgent(event_bus, config={"false_positive_patterns": ["health check"]})
    await agent.initialize()

    event = Event(
        event_type=EventType.ALERT_RECEIVED,
        data={"description": "health check failed from monitoring system", "severity": "low"},
    )
    result = await agent.process(event)

    assert result.action == "false_positive"


@pytest.mark.asyncio
async def test_triage_escalation(event_bus):
    escalated = []

    async def handler(event: Event):
        escalated.append(event)

    event_bus.subscribe(EventType.ALERT_ESCALATED, handler)

    agent = TriageAgent(event_bus)
    await agent.initialize()

    event = Event(
        event_type=EventType.ALERT_RECEIVED,
        data={"severity": "critical", "description": "Ransomware detected on server", "source_ip": "10.0.0.5"},
    )
    await agent.process(event)

    assert len(escalated) == 1


# --- Threat Hunter ---

@pytest.mark.asyncio
async def test_threat_hunter_ioc_matching(event_bus):
    agent = ThreatHunterAgent(event_bus)
    await agent.initialize()
    agent.add_ioc("ip", "198.51.100.1", "threat_feed")

    event = Event(
        event_type=EventType.ALERT_RECEIVED,
        data={"source_ip": "198.51.100.1", "description": "outbound connection"},
    )
    result = await agent.process(event)

    assert result.data["findings_count"] > 0


@pytest.mark.asyncio
async def test_threat_hunter_autonomous(event_bus):
    agent = ThreatHunterAgent(event_bus)
    await agent.initialize()

    results = await agent.run_autonomous()
    assert len(results) == 5  # One per hypothesis


# --- Incident Responder ---

@pytest.mark.asyncio
async def test_incident_creation(event_bus):
    agent = IncidentResponderAgent(event_bus)
    await agent.initialize()

    event = Event(
        event_type=EventType.THREAT_DETECTED,
        data={"attack_type": "brute_force", "severity": "high", "source_ip": "10.0.0.99"},
    )
    result = await agent.process(event)

    assert result.success
    assert "incident_id" in result.data
    assert result.data["severity"] == "high"

    incidents = agent.list_incidents(status="open")
    assert len(incidents) == 1


@pytest.mark.asyncio
async def test_incident_close(event_bus):
    agent = IncidentResponderAgent(event_bus)
    await agent.initialize()

    event = Event(
        event_type=EventType.THREAT_DETECTED,
        data={"attack_type": "malware", "severity": "critical"},
    )
    result = await agent.process(event)
    incident_id = result.data["incident_id"]

    success = agent.close_incident(incident_id, "Malware quarantined and host reimaged")
    assert success

    incident = agent.get_incident(incident_id)
    assert incident.status == "closed"


# --- Compliance Auditor ---

@pytest.mark.asyncio
async def test_compliance_full_audit(event_bus):
    agent = ComplianceAuditorAgent(event_bus)
    await agent.initialize()

    results = await agent.run_autonomous()
    assert len(results) == 1
    assert results[0].data["total_checks"] > 0


@pytest.mark.asyncio
async def test_compliance_report(event_bus):
    agent = ComplianceAuditorAgent(event_bus)
    await agent.initialize()
    await agent.run_autonomous()

    report = agent.get_compliance_report(framework="CIS")
    assert report["framework"] == "CIS"
    assert "compliance_score" in report


# --- Forensic Analyst ---

@pytest.mark.asyncio
async def test_forensic_investigation(event_bus):
    agent = ForensicAnalystAgent(event_bus)
    await agent.initialize()

    event = Event(
        event_type=EventType.INCIDENT_CREATED,
        data={
            "incident_id": "INC-001",
            "source_ip": "203.0.113.50",
            "destination_ip": "10.0.0.5",
            "process_name": "powershell.exe",
            "command_line": "powershell -enc SGVsbG8=",
            "hostname": "WORKSTATION-01",
        },
    )
    result = await agent.process(event)

    assert result.success
    assert result.data["evidence_count"] >= 3  # network + process + raw
    assert result.data["iocs_found"] >= 1  # external IP
    assert result.data["findings_count"] >= 1  # suspicious powershell


# --- Vuln Scanner ---

@pytest.mark.asyncio
async def test_vuln_scanner_autonomous(event_bus):
    agent = VulnScannerAgent(event_bus)
    await agent.initialize()

    results = await agent.run_autonomous()
    assert len(results) == 1
    assert results[0].data["checks_run"] > 0


@pytest.mark.asyncio
async def test_vuln_report(event_bus):
    agent = VulnScannerAgent(event_bus)
    await agent.initialize()
    await agent.run_autonomous()

    report = agent.get_vulnerability_report()
    assert "total" in report
    assert "by_severity" in report
