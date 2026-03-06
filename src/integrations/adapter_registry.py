"""Dynamic adapter discovery and registration."""

from __future__ import annotations

import logging
from typing import Any

from src.integrations.base_adapter import BaseSecurityAdapter

logger = logging.getLogger(__name__)


class AdapterRegistry:
    """Registry for dynamically discovering and managing security product adapters."""

    def __init__(self) -> None:
        self._adapter_classes: dict[str, type[BaseSecurityAdapter]] = {}
        self._instances: dict[str, BaseSecurityAdapter] = {}

    def register_class(self, vendor: str, adapter_class: type[BaseSecurityAdapter]) -> None:
        """Register an adapter class by vendor name."""
        self._adapter_classes[vendor] = adapter_class
        logger.info("Registered adapter class: %s", vendor)

    def create_adapter(self, vendor: str, config: dict[str, Any]) -> BaseSecurityAdapter:
        """Create an adapter instance from a registered class."""
        if vendor not in self._adapter_classes:
            raise ValueError(f"Unknown adapter vendor: {vendor}. Registered: {list(self._adapter_classes.keys())}")
        adapter = self._adapter_classes[vendor](config)
        instance_name = f"{vendor}_{config.get('name', 'default')}"
        self._instances[instance_name] = adapter
        return adapter

    def get_adapter(self, name: str) -> BaseSecurityAdapter | None:
        return self._instances.get(name)

    def list_adapters(self) -> dict[str, dict[str, Any]]:
        return {
            name: {
                "vendor": adapter.vendor,
                "product_type": adapter.product_type,
                "connected": adapter.is_connected,
                "endpoint": adapter.endpoint,
            }
            for name, adapter in self._instances.items()
        }

    def auto_register_builtin(self) -> None:
        """Register all built-in adapter classes."""
        from src.integrations.firewall_adapter import PaloAltoAdapter, FortinetAdapter
        from src.integrations.waf_adapter import CloudflareWAFAdapter, AWSWAFAdapter
        from src.integrations.siem_adapter import WazuhAdapter, SplunkAdapter
        from src.integrations.identity_adapter import EntraIDAdapter, OktaAdapter
        from src.integrations.edr_adapter import CrowdStrikeAdapter, SentinelOneAdapter
        from src.integrations.soar_adapter import ShuffleAdapter, TracecatAdapter

        for cls in [
            PaloAltoAdapter, FortinetAdapter,
            CloudflareWAFAdapter, AWSWAFAdapter,
            WazuhAdapter, SplunkAdapter,
            EntraIDAdapter, OktaAdapter,
            CrowdStrikeAdapter, SentinelOneAdapter,
            ShuffleAdapter, TracecatAdapter,
        ]:
            self.register_class(cls.vendor, cls)

    async def connect_from_config(self, adapters_config: list[dict]) -> list[BaseSecurityAdapter]:
        """Create and connect adapters from configuration."""
        connected = []
        for adapter_cfg in adapters_config:
            vendor = adapter_cfg.get("vendor", "")
            try:
                adapter = self.create_adapter(vendor, adapter_cfg)
                await adapter.connect()
                connected.append(adapter)
            except Exception:
                logger.exception("Failed to create/connect adapter: %s", vendor)
        return connected
