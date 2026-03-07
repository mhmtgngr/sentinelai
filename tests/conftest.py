"""Common test fixtures for Sentinel-AI."""

from __future__ import annotations

from datetime import datetime

import pytest

from src.core.event_bus import EventBus
from src.core.models import (
    Alert,
    IOC,
    SecurityEvent,
    Severity,
    Verdict,
)


@pytest.fixture
def event_bus() -> EventBus:
    """Create a fresh event bus for testing."""
    return EventBus(max_queue_size=100)


@pytest.fixture
def sample_security_event() -> SecurityEvent:
    """A sample brute-force SSH security event."""
    return SecurityEvent(
        source_adapter="wazuh",
        timestamp=datetime(2024, 1, 15, 10, 30, 0),
        severity=Severity.HIGH,
        event_type="brute_force",
        raw_payload={
            "rule": {"id": "5710", "description": "sshd: Attempt to login using a non-existent user"},
            "agent": {"name": "web-server-01"},
        },
        normalized={
            "source_ip": "203.0.113.42",
            "target_host": "web-server-01",
            "service": "ssh",
            "attempt_count": 50,
        },
        mitre_attack=["T1110.001"],
        affected_assets=["web-server-01", "203.0.113.42"],
        iocs=[
            IOC(type="ip", value="203.0.113.42", confidence=0.95, source="wazuh"),
        ],
    )


@pytest.fixture
def sample_alert(sample_security_event: SecurityEvent) -> Alert:
    """A sample triaged alert."""
    return Alert(
        events=[sample_security_event],
        triage_verdict=Verdict.TRUE_POSITIVE,
        confidence_score=0.87,
        priority=10,
        assigned_agent="threat_hunter",
        mitre_tactic="Credential Access",
        enrichment={"threat_intel": {"ip_reputation": "malicious"}},
    )
