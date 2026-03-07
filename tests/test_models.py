"""Tests for core data models."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from src.core.models import (
    ActionResult,
    ActionStatus,
    ActionType,
    AgentDecision,
    Alert,
    Asset,
    HandoffPayload,
    HealthState,
    HealthStatus,
    IOC,
    Incident,
    IncidentStatus,
    SecurityEvent,
    Severity,
    TimelineEntry,
    Verdict,
)


class TestSecurityEvent:
    def test_create_minimal(self) -> None:
        event = SecurityEvent(source_adapter="wazuh", event_type="brute_force")
        assert event.source_adapter == "wazuh"
        assert event.event_type == "brute_force"
        assert event.severity == Severity.INFO
        assert event.schema_version == 1
        assert event.id  # Auto-generated

    def test_create_full(self, sample_security_event: SecurityEvent) -> None:
        assert sample_security_event.severity == Severity.HIGH
        assert len(sample_security_event.iocs) == 1
        assert sample_security_event.mitre_attack == ["T1110.001"]

    def test_serialization_roundtrip(self, sample_security_event: SecurityEvent) -> None:
        data = sample_security_event.model_dump()
        restored = SecurityEvent.model_validate(data)
        assert restored.source_adapter == sample_security_event.source_adapter
        assert restored.iocs[0].value == "203.0.113.42"


class TestAlert:
    def test_create_minimal(self) -> None:
        alert = Alert()
        assert alert.triage_verdict == Verdict.UNDETERMINED
        assert alert.confidence_score == 0.0
        assert alert.id

    def test_confidence_score_bounds(self) -> None:
        alert = Alert(confidence_score=0.87)
        assert alert.confidence_score == 0.87

        with pytest.raises(ValidationError):
            Alert(confidence_score=1.5)

        with pytest.raises(ValidationError):
            Alert(confidence_score=-0.1)


class TestActionResult:
    def test_create(self) -> None:
        result = ActionResult(
            action_type=ActionType.BLOCK_IP,
            target="203.0.113.42",
            status=ActionStatus.SUCCESS,
            adapter_used="paloalto",
            rollback_capable=True,
            rollback_procedure="Remove firewall rule #12345",
        )
        assert result.action_type == ActionType.BLOCK_IP
        assert result.rollback_capable is True

    def test_default_status(self) -> None:
        result = ActionResult(action_type=ActionType.BLOCK_IP, target="1.2.3.4")
        assert result.status == ActionStatus.PENDING


class TestAgentDecision:
    def test_create(self) -> None:
        decision = AgentDecision(
            agent_id="triage",
            alert_id="ALT-001",
            confidence=0.87,
            reasoning_trace=["Matched known IOC", "High severity SSH brute force"],
            recommended_actions=[{"type": "BLOCK_IP", "target": "203.0.113.42"}],
            data_sources_consulted=["wazuh_siem", "threat_intel_cache"],
        )
        assert decision.confidence == 0.87
        assert len(decision.reasoning_trace) == 2

    def test_confidence_bounds(self) -> None:
        with pytest.raises(ValidationError):
            AgentDecision(agent_id="test", confidence=1.5)


class TestIncident:
    def test_create_with_timeline(self) -> None:
        incident = Incident(
            status=IncidentStatus.INVESTIGATING,
            timeline=[
                TimelineEntry(description="Alert triaged as TRUE_POSITIVE"),
                TimelineEntry(description="Threat hunt initiated"),
            ],
            affected_assets=[
                Asset(identifier="web-server-01", asset_type="host", criticality="high"),
            ],
        )
        assert incident.status == IncidentStatus.INVESTIGATING
        assert len(incident.timeline) == 2
        assert incident.affected_assets[0].criticality == "high"


class TestHandoffPayload:
    def test_create(self) -> None:
        decision = AgentDecision(agent_id="triage", confidence=0.87)
        handoff = HandoffPayload(
            source_agent="triage",
            target_agent="threat_hunter",
            alert_id="ALT-001",
            decision=decision,
            priority=10,
        )
        assert handoff.is_complete is True
        assert handoff.follow_up_required is False


class TestIOC:
    def test_confidence_bounds(self) -> None:
        ioc = IOC(type="ip", value="1.2.3.4", confidence=0.95)
        assert ioc.confidence == 0.95

        with pytest.raises(ValidationError):
            IOC(type="ip", value="1.2.3.4", confidence=1.5)


class TestHealthStatus:
    def test_defaults(self) -> None:
        status = HealthStatus()
        assert status.state == HealthState.HEALTHY
        assert status.message == ""
