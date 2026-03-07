"""Dynamic adapter discovery and registration.

Manages the lifecycle of all security product adapters.
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.models import HealthStatus
from src.integrations.base_adapter import BaseSecurityAdapter

logger = logging.getLogger(__name__)


class AdapterRegistry:
    """Registry for security product adapters.

    Manages adapter instances, provides lookup by type/vendor,
    and aggregates health status.
    """

    def __init__(self) -> None:
        self._adapters: dict[str, BaseSecurityAdapter] = {}

    def register(self, adapter_id: str, adapter: BaseSecurityAdapter) -> None:
        """Register an adapter instance."""
        self._adapters[adapter_id] = adapter
        logger.info(
            "Registered adapter '%s' (%s/%s)",
            adapter_id,
            adapter.product_type,
            adapter.vendor,
        )

    def unregister(self, adapter_id: str) -> None:
        """Remove an adapter from the registry."""
        if adapter_id in self._adapters:
            del self._adapters[adapter_id]
            logger.info("Unregistered adapter '%s'", adapter_id)

    def get(self, adapter_id: str) -> BaseSecurityAdapter | None:
        """Get an adapter by ID."""
        return self._adapters.get(adapter_id)

    def get_by_type(self, product_type: str) -> list[BaseSecurityAdapter]:
        """Get all adapters of a given product type (e.g., 'firewall')."""
        return [a for a in self._adapters.values() if a.product_type == product_type]

    def get_by_vendor(self, vendor: str) -> list[BaseSecurityAdapter]:
        """Get all adapters for a given vendor."""
        return [a for a in self._adapters.values() if a.vendor == vendor]

    async def health_check_all(self) -> dict[str, HealthStatus]:
        """Run health checks on all registered adapters."""
        results: dict[str, HealthStatus] = {}
        for adapter_id, adapter in self._adapters.items():
            try:
                results[adapter_id] = await adapter.health_check()
            except Exception as e:
                results[adapter_id] = HealthStatus(
                    state="UNAVAILABLE",
                    message=str(e),
                )
        return results

    @property
    def adapter_ids(self) -> list[str]:
        """List all registered adapter IDs."""
        return list(self._adapters.keys())

    @property
    def count(self) -> int:
        """Number of registered adapters."""
        return len(self._adapters)

    def get_all(self) -> dict[str, Any]:
        """Get summary info for all adapters."""
        return {
            adapter_id: {
                "product_type": adapter.product_type,
                "vendor": adapter.vendor,
                "health_state": adapter.health_state.value,
            }
            for adapter_id, adapter in self._adapters.items()
        }
