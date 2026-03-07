"""Tests for AdapterRegistry."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.models import HealthState
from src.integrations.adapter_registry import AdapterRegistry


def _mock_adapter(product_type: str, vendor: str, health: HealthState = HealthState.HEALTHY):
    adapter = MagicMock()
    adapter.product_type = product_type
    adapter.vendor = vendor
    adapter.health_state = health
    adapter.health_check = AsyncMock(return_value=MagicMock(state=health))
    return adapter


def test_register_and_get():
    registry = AdapterRegistry()
    adapter = _mock_adapter("firewall", "paloalto")
    registry.register("fw-1", adapter)
    assert registry.get("fw-1") is adapter


def test_get_nonexistent():
    registry = AdapterRegistry()
    assert registry.get("nope") is None


def test_unregister():
    registry = AdapterRegistry()
    adapter = _mock_adapter("firewall", "paloalto")
    registry.register("fw-1", adapter)
    registry.unregister("fw-1")
    assert registry.get("fw-1") is None


def test_get_by_type():
    registry = AdapterRegistry()
    fw = _mock_adapter("firewall", "paloalto")
    waf = _mock_adapter("waf", "cloudflare")
    registry.register("fw-1", fw)
    registry.register("waf-1", waf)
    firewalls = registry.get_by_type("firewall")
    assert len(firewalls) == 1
    assert firewalls[0] is fw


def test_get_by_vendor():
    registry = AdapterRegistry()
    fw = _mock_adapter("firewall", "paloalto")
    edr = _mock_adapter("edr", "paloalto")
    waf = _mock_adapter("waf", "cloudflare")
    registry.register("fw-1", fw)
    registry.register("edr-1", edr)
    registry.register("waf-1", waf)
    pa_adapters = registry.get_by_vendor("paloalto")
    assert len(pa_adapters) == 2


def test_count():
    registry = AdapterRegistry()
    assert registry.count == 0
    registry.register("a", _mock_adapter("firewall", "pa"))
    registry.register("b", _mock_adapter("waf", "cf"))
    assert registry.count == 2


def test_adapter_ids():
    registry = AdapterRegistry()
    registry.register("fw-1", _mock_adapter("firewall", "pa"))
    registry.register("waf-1", _mock_adapter("waf", "cf"))
    ids = registry.adapter_ids
    assert set(ids) == {"fw-1", "waf-1"}


def test_get_all():
    registry = AdapterRegistry()
    fw = _mock_adapter("firewall", "paloalto")
    registry.register("fw-1", fw)
    all_adapters = registry.get_all()
    assert isinstance(all_adapters, dict)
    assert "fw-1" in all_adapters


@pytest.mark.asyncio
async def test_health_check_all():
    registry = AdapterRegistry()
    fw = _mock_adapter("firewall", "paloalto")
    waf = _mock_adapter("waf", "cloudflare")
    registry.register("fw-1", fw)
    registry.register("waf-1", waf)
    results = await registry.health_check_all()
    assert isinstance(results, dict)
    assert "fw-1" in results
    assert "waf-1" in results
