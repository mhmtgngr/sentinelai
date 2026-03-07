"""Tests for concrete adapter implementations."""

from __future__ import annotations

import pytest

from src.core.models import HealthState, HealthStatus


class TestFirewallAdapter:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.integrations.firewall_adapter import FirewallAdapter
        assert FirewallAdapter is not None

    @pytest.mark.asyncio
    async def test_creation(self):
        from src.integrations.firewall_adapter import FirewallAdapter
        adapter = FirewallAdapter(
            endpoint="https://fw.example.com",
            api_key="test-key",
        )
        assert adapter.product_type == "firewall"
        assert adapter.vendor == "paloalto"
        assert adapter.endpoint == "https://fw.example.com"

    @pytest.mark.asyncio
    async def test_health_check_unreachable(self):
        from src.integrations.firewall_adapter import FirewallAdapter
        adapter = FirewallAdapter(
            endpoint="https://fw.example.com",
            api_key="test-key",
        )
        result = await adapter.health_check()
        assert isinstance(result, HealthStatus)
        assert result.state == HealthState.UNAVAILABLE

    @pytest.mark.asyncio
    async def test_health_state_property(self):
        from src.integrations.firewall_adapter import FirewallAdapter
        adapter = FirewallAdapter(endpoint="https://fw.example.com")
        assert adapter.health_state == HealthState.HEALTHY  # circuit breaker starts closed


class TestWAFAdapter:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.integrations.waf_adapter import WAFAdapter
        assert WAFAdapter is not None

    @pytest.mark.asyncio
    async def test_creation(self):
        from src.integrations.waf_adapter import WAFAdapter
        adapter = WAFAdapter(
            endpoint="https://api.cloudflare.com",
            api_token="test-token",
            zone_id="zone-1",
        )
        assert adapter.product_type == "waf"
        assert adapter.vendor == "cloudflare"


class TestSIEMAdapter:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.integrations.siem_adapter import SIEMAdapter
        assert SIEMAdapter is not None

    @pytest.mark.asyncio
    async def test_creation(self):
        from src.integrations.siem_adapter import SIEMAdapter
        adapter = SIEMAdapter(
            endpoint="https://wazuh.example.com",
            username="admin",
            password="secret",
        )
        assert adapter.product_type == "siem"
        assert adapter.vendor == "wazuh"


class TestIdentityAdapter:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.integrations.identity_adapter import IdentityAdapter
        assert IdentityAdapter is not None

    @pytest.mark.asyncio
    async def test_creation(self):
        from src.integrations.identity_adapter import IdentityAdapter
        adapter = IdentityAdapter(
            endpoint="https://graph.microsoft.com",
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="secret",
        )
        assert adapter.product_type == "identity"
        assert adapter.vendor == "entraid"


class TestEDRAdapter:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.integrations.edr_adapter import EDRAdapter
        assert EDRAdapter is not None

    @pytest.mark.asyncio
    async def test_creation(self):
        from src.integrations.edr_adapter import EDRAdapter
        adapter = EDRAdapter(
            endpoint="https://api.crowdstrike.com",
            client_id="client-1",
            client_secret="secret",
        )
        assert adapter.product_type == "edr"
        assert adapter.vendor == "crowdstrike"


class TestSOARAdapter:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.integrations.soar_adapter import SOARAdapter
        assert SOARAdapter is not None

    @pytest.mark.asyncio
    async def test_creation(self):
        from src.integrations.soar_adapter import SOARAdapter
        adapter = SOARAdapter(
            endpoint="https://shuffle.example.com",
            api_key="test-key",
        )
        assert adapter.product_type == "soar"
        assert adapter.vendor == "shuffle"
