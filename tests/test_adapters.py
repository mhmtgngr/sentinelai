"""Tests for adapter system."""

import pytest
from src.integrations.base_adapter import BaseSecurityAdapter, HealthStatus, SecurityEvent
from src.integrations.adapter_registry import AdapterRegistry
from src.integrations.firewall_adapter import PaloAltoAdapter


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
    assert "qradar" in listed_classes
    assert "entra_id" in listed_classes
    assert "defender_xdr" in listed_classes
    assert "exchange_online" in listed_classes
    assert "teams" in listed_classes
    assert "security_center" in listed_classes


def test_qradar_magnitude_mapping():
    from src.integrations.siem_adapter import QRadarAdapter
    assert QRadarAdapter._map_magnitude(9) == "critical"
    assert QRadarAdapter._map_magnitude(7) == "high"
    assert QRadarAdapter._map_magnitude(5) == "medium"
    assert QRadarAdapter._map_magnitude(3) == "low"
    assert QRadarAdapter._map_magnitude(1) == "info"


def test_qradar_tactic_inference():
    from src.integrations.siem_adapter import QRadarAdapter
    assert QRadarAdapter._infer_tactic(["Recon", "Port Scan"]) == "Reconnaissance"
    assert QRadarAdapter._infer_tactic(["Exploit", "Buffer Overflow"]) == "Initial Access"
    assert QRadarAdapter._infer_tactic(["Malware", "Trojan"]) == "Execution"
    assert QRadarAdapter._infer_tactic(["Lateral Movement"]) == "Lateral Movement"
    assert QRadarAdapter._infer_tactic(["Exfiltration"]) == "Exfiltration"
    assert QRadarAdapter._infer_tactic(["Unknown"]) == ""


def test_defender_xdr_adapter_init():
    from src.integrations.edr_adapter import DefenderXDRAdapter
    adapter = DefenderXDRAdapter({
        "endpoint": "",
        "tenant_id": "test-tenant",
        "client_id": "test-client",
    })
    assert adapter.vendor == "defender_xdr"
    assert adapter.product_type == "edr"


def test_exchange_online_adapter_init():
    from src.integrations.microsoft_adapter import ExchangeOnlineAdapter
    adapter = ExchangeOnlineAdapter({"endpoint": ""})
    assert adapter.vendor == "exchange_online"
    assert adapter.product_type == "email_security"


def test_teams_adapter_init():
    from src.integrations.microsoft_adapter import TeamsAdapter
    adapter = TeamsAdapter({
        "endpoint": "",
        "webhook_url": "https://webhook.example.com/test",
    })
    assert adapter.vendor == "teams"
    assert adapter.product_type == "collaboration"
    assert adapter._webhook_url == "https://webhook.example.com/test"


def test_security_center_adapter_init():
    from src.integrations.microsoft_adapter import SecurityCenterAdapter
    adapter = SecurityCenterAdapter({"endpoint": ""})
    assert adapter.vendor == "security_center"
    assert adapter.product_type == "security_center"
