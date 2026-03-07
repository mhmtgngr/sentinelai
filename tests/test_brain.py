"""Tests for the Brain coordinator."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.brain import Brain
from src.core.event_bus import EventBus
from src.core.models import (
    AgentDecision,
    Alert,
    IOC,
    SecurityEvent,
    Severity,
)
from src.integrations.adapter_registry import AdapterRegistry


def _make_alert(iocs: list[IOC] | None = None) -> Alert:
    event = SecurityEvent(
        source_adapter="test",
        event_type="test_event",
        severity=Severity.HIGH,
        raw_payload={"key": "value"},
        iocs=iocs or [],
    )
    return Alert(events=[event])


def _make_decision(
    agent_id: str = "triage",
    confidence: float = 0.9,
    actions: list | None = None,
) -> AgentDecision:
    return AgentDecision(
        agent_id=agent_id,
        confidence=confidence,
        reasoning_trace=["test"],
        recommended_actions=actions or [],
        data_sources_consulted=["siem", "threat_intel"],
    )


def _mock_agent(agent_id: str, decision: AgentDecision | None = None):
    agent = MagicMock()
    agent.agent_id = agent_id
    agent.capabilities = [agent_id]
    if decision:
        agent.execute = AsyncMock(return_value=decision)
    else:
        agent.execute = AsyncMock(return_value=_make_decision(agent_id=agent_id))
    return agent


@pytest.fixture
def brain_components():
    event_bus = EventBus()
    registry = AdapterRegistry()
    agents = {
        "triage": _mock_agent("triage"),
        "threat_hunter": _mock_agent("threat_hunter"),
        "incident_responder": _mock_agent("incident_responder"),
        "forensic_analyst": _mock_agent("forensic_analyst"),
        "compliance_auditor": _mock_agent("compliance_auditor"),
        "vuln_scanner": _mock_agent("vuln_scanner"),
    }
    brain = Brain(
        event_bus=event_bus,
        agents=agents,
        adapter_registry=registry,
        shadow_mode=True,
    )
    return brain, event_bus, agents


@pytest.mark.asyncio
async def test_brain_creation(brain_components):
    brain, _, _ = brain_components
    assert brain._shadow_mode is True
    assert brain.queue_depth == 0


@pytest.mark.asyncio
async def test_brain_agent_dict(brain_components):
    brain, _, agents = brain_components
    assert "triage" in brain._agents
    assert len(brain._agents) == 6


@pytest.mark.asyncio
async def test_deduplication_no_match(brain_components):
    brain, _, _ = brain_components
    alert = _make_alert()
    result = brain._check_deduplication(alert)
    assert result is None


@pytest.mark.asyncio
async def test_deduplication_with_iocs(brain_components):
    brain, _, _ = brain_components
    ioc = IOC(type="ip", value="10.0.0.1", confidence=0.9)

    alert1 = _make_alert(iocs=[ioc])
    # First alert should register and return None (no dup)
    result1 = brain._check_deduplication(alert1)
    assert result1 is None

    # Track alert1 as active
    brain._active_alerts[alert1.id] = alert1

    # Second alert with same IOC should detect overlap
    alert2 = _make_alert(iocs=[IOC(type="ip", value="10.0.0.1", confidence=0.9)])
    result2 = brain._check_deduplication(alert2)
    assert result2 is not None
    assert result2.id == alert1.id


@pytest.mark.asyncio
async def test_validate_action_high_confidence(brain_components):
    brain, _, _ = brain_components
    action = {"type": "BLOCK_IP", "target": "10.0.0.1"}
    decision = _make_decision(confidence=0.9)
    result = brain._validate_action(action, decision)
    assert result is True


@pytest.mark.asyncio
async def test_validate_action_low_confidence(brain_components):
    brain, _, _ = brain_components
    action = {"type": "BLOCK_IP", "target": "10.0.0.1"}
    decision = _make_decision(confidence=0.3)
    result = brain._validate_action(action, decision)
    assert result is False


@pytest.mark.asyncio
async def test_validate_action_invalid_type(brain_components):
    brain, _, _ = brain_components
    action = {"type": "INVALID_ACTION", "target": "10.0.0.1"}
    decision = _make_decision(confidence=0.9)
    result = brain._validate_action(action, decision)
    assert result is False


@pytest.mark.asyncio
async def test_resolve_conflict_picks_highest_authority(brain_components):
    brain, _, _ = brain_components
    d1 = _make_decision(agent_id="triage", confidence=0.8)
    d2 = _make_decision(agent_id="compliance_auditor", confidence=0.7)
    result = brain._resolve_conflict([d1, d2])
    assert isinstance(result, AgentDecision)
    # compliance_auditor has authority 1 (highest), triage has 5
    assert result.agent_id == "compliance_auditor"


@pytest.mark.asyncio
async def test_resolve_conflict_single_decision(brain_components):
    brain, _, _ = brain_components
    d1 = _make_decision(agent_id="triage", confidence=0.8)
    result = brain._resolve_conflict([d1])
    assert result is d1


@pytest.mark.asyncio
async def test_brain_start(brain_components):
    brain, event_bus, _ = brain_components
    await event_bus.start()
    await brain.start()
    await event_bus.stop()


@pytest.mark.asyncio
async def test_brain_active_alert_count(brain_components):
    brain, _, _ = brain_components
    assert brain.active_alert_count == 0
