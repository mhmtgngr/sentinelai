"""Tests for adapter system."""

import pytest
from src.integrations.base_adapter import BaseSecurityAdapter, HealthStatus, SecurityEvent
from src.integrations.adapter_registry import AdapterRegistry
from src.integrations.firewall_adapter import PaloAltoAdapter, FortinetAdapter


class MockAdapter(BaseSecurityAdapter):
    product_type = "test"
    vendor = "mock"

    async def _authenticate(self):
        pass

    async def get_events(self, since=None):
        return [self._build_event({"test": True}, event_type="test_event", severity="low")]

    async def health_check(self):
        return HealthStatus.HEALTHY


def test_adapter_registry():
    registry = AdapterRegistry()
    registry.register_class("mock", MockAdapter)

    adapter = registry.create_adapter("mock", {"name": "test1", "endpoint": "http://localhost"})
    assert adapter.vendor == "mock"
    assert adapter.product_type == "test"

    listed = registry.list_adapters()
    assert "mock_test1" in listed


def test_registry_unknown_vendor():
    registry = AdapterRegistry()
    with pytest.raises(ValueError, match="Unknown adapter vendor"):
        registry.create_adapter("nonexistent", {})


@pytest.mark.asyncio
async def test_mock_adapter_events():
    adapter = MockAdapter({"endpoint": "http://test"})
    await adapter.connect()

    assert adapter.is_connected
    events = await adapter.get_events()
    assert len(events) == 1
    assert events[0]["event_type"] == "test_event"


@pytest.mark.asyncio
async def test_mock_adapter_health():
    adapter = MockAdapter({"endpoint": "http://test"})
    await adapter.connect()
    health = await adapter.health_check()
    assert health == HealthStatus.HEALTHY


@pytest.mark.asyncio
async def test_adapter_disconnect():
    adapter = MockAdapter({"endpoint": "http://test"})
    await adapter.connect()
    assert adapter.is_connected
    await adapter.disconnect()
    assert not adapter.is_connected


def test_security_event_creation():
    event = SecurityEvent(
        source="test",
        event_type="alert",
        severity="high",
        description="Test alert",
        source_ip="10.0.0.1",
    )
    assert event.event_id
    assert event.source == "test"
    assert event.severity == "high"


def test_auto_register_builtin():
    registry = AdapterRegistry()
    registry.auto_register_builtin()
    listed_classes = list(registry._adapter_classes.keys())
    assert "paloalto" in listed_classes
    assert "wazuh" in listed_classes
    assert "crowdstrike" in listed_classes
    assert "cloudflare" in listed_classes
    assert "entra_id" in listed_classes
    assert "shuffle" in listed_classes
