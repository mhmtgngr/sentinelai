"""Tests for BaseAgent."""

from __future__ import annotations

import asyncio

import pytest

from src.agents.base_agent import BaseAgent
from src.core.models import AgentDecision, Alert, SecurityEvent, Severity


class MockAgent(BaseAgent):
    """Concrete agent for testing."""

    @property
    def capabilities(self) -> list[str]:
        return ["test", "mock"]

    async def process(self, alert: Alert) -> AgentDecision:
        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=0.9,
            reasoning_trace=["test reasoning"],
            recommended_actions=[],
        )


class SlowAgent(BaseAgent):
    """Agent that exceeds timeout."""

    @property
    def capabilities(self) -> list[str]:
        return ["slow"]

    async def process(self, alert: Alert) -> AgentDecision:
        await asyncio.sleep(10)
        return AgentDecision(
            agent_id=self.agent_id,
            alert_id=alert.id,
            confidence=0.5,
            reasoning_trace=[],
            recommended_actions=[],
        )


class FailingAgent(BaseAgent):
    """Agent that raises errors."""

    @property
    def capabilities(self) -> list[str]:
        return ["fail"]

    async def process(self, alert: Alert) -> AgentDecision:
        raise ValueError("Something went wrong")


def _make_alert() -> Alert:
    event = SecurityEvent(
        source_adapter="test",
        event_type="test_event",
        severity=Severity.HIGH,
        raw_payload={"key": "value"},
    )
    return Alert(events=[event])


@pytest.mark.asyncio
async def test_agent_capabilities():
    agent = MockAgent(agent_id="test-agent")
    assert agent.capabilities == ["test", "mock"]


@pytest.mark.asyncio
async def test_agent_execute_success():
    agent = MockAgent(agent_id="test-agent")
    alert = _make_alert()
    decision = await agent.execute(alert)
    assert decision.confidence == 0.9
    assert decision.alert_id == alert.id


@pytest.mark.asyncio
async def test_agent_execute_timeout():
    agent = SlowAgent(agent_id="slow-agent", timeout_seconds=0.1)
    alert = _make_alert()
    decision = await agent.execute(alert)
    assert decision.confidence == 0.0


@pytest.mark.asyncio
async def test_agent_execute_error():
    agent = FailingAgent(agent_id="fail-agent")
    alert = _make_alert()
    decision = await agent.execute(alert)
    assert decision.confidence == 0.0


@pytest.mark.asyncio
async def test_agent_meets_confidence_threshold():
    agent = MockAgent(agent_id="test-agent", confidence_threshold=0.8)
    decision = AgentDecision(
        agent_id="test-agent",
        confidence=0.9,
        reasoning_trace=[],
        recommended_actions=[],
    )
    assert agent.meets_confidence_threshold(decision) is True


@pytest.mark.asyncio
async def test_agent_below_confidence_threshold():
    agent = MockAgent(agent_id="test-agent", confidence_threshold=0.95)
    decision = AgentDecision(
        agent_id="test-agent",
        confidence=0.9,
        reasoning_trace=[],
        recommended_actions=[],
    )
    assert agent.meets_confidence_threshold(decision) is False


@pytest.mark.asyncio
async def test_agent_id_preserved():
    agent = MockAgent(agent_id="my-agent-42")
    assert agent.agent_id == "my-agent-42"


@pytest.mark.asyncio
async def test_agent_default_timeout():
    agent = MockAgent(agent_id="test")
    assert agent.timeout_seconds == 60.0


@pytest.mark.asyncio
async def test_agent_is_processing_flag():
    agent = MockAgent(agent_id="test")
    assert agent.is_processing is False
