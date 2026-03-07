"""Firewall Adapter — Palo Alto PAN-OS integration.

Provides event ingestion and action execution against PAN-OS firewalls.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from src.core.models import (
    ActionResult,
    ActionStatus,
    ActionType,
    HealthState,
    HealthStatus,
    SecurityEvent,
    Severity,
)
from src.integrations.base_adapter import BaseSecurityAdapter

logger = logging.getLogger(__name__)


class FirewallAdapter(BaseSecurityAdapter):
    """Palo Alto PAN-OS firewall adapter."""

    product_type = "firewall"
    vendor = "paloalto"

    def __init__(self, endpoint: str, api_key: str = "", **kwargs: Any) -> None:
        super().__init__(endpoint, **kwargs)
        self._api_key = api_key
        self._client = httpx.AsyncClient(
            base_url=endpoint,
            headers={"X-PAN-KEY": api_key},
            verify=False,
            timeout=30.0,
        )

    async def get_events(self, since: datetime) -> list[SecurityEvent]:
        """Poll PAN-OS for traffic and threat logs."""
        params = {
            "type": "log",
            "log-type": "threat",
            "query": f"(receive_time geq '{since.strftime('%Y/%m/%d %H:%M:%S')}')",
        }

        response = await self._client.get("/api/", params=params)
        response.raise_for_status()

        events: list[SecurityEvent] = []
        for entry in self._parse_panos_response(response.text):
            events.append(SecurityEvent(
                source_adapter=f"{self.product_type}/{self.vendor}",
                event_type=entry.get("type", "threat"),
                severity=self._map_severity(entry.get("severity", "low")),
                raw_payload=entry,
                normalized={
                    "source_ip": entry.get("src"),
                    "destination_ip": entry.get("dst"),
                    "application": entry.get("app"),
                    "action": entry.get("action"),
                },
                affected_assets=[
                    a for a in [entry.get("src"), entry.get("dst")] if a
                ],
            ))

        return events

    async def execute_action(
        self, action_type: ActionType, target: str, params: dict[str, Any] | None = None
    ) -> ActionResult:
        """Execute a firewall action (block/unblock IP)."""
        if action_type == ActionType.BLOCK_IP:
            return await self._block_ip(target)
        elif action_type == ActionType.UNBLOCK_IP:
            return await self._unblock_ip(target)

        return ActionResult(
            action_type=action_type,
            target=target,
            status=ActionStatus.FAILED,
            adapter_used=f"{self.product_type}/{self.vendor}",
            evidence={"error": f"Unsupported action: {action_type.value}"},
        )

    async def _block_ip(self, ip: str) -> ActionResult:
        """Add an IP to the block list via PAN-OS API."""
        request_params = {
            "type": "config",
            "action": "set",
            "xpath": f"/config/devices/entry/vsys/entry/address/entry[@name='blocked-{ip}']",
            "element": f"<ip-netmask>{ip}/32</ip-netmask>",
        }

        try:
            response = await self._client.post("/api/", params=request_params)
            response.raise_for_status()

            return ActionResult(
                action_type=ActionType.BLOCK_IP,
                target=ip,
                status=ActionStatus.SUCCESS,
                adapter_used=f"{self.product_type}/{self.vendor}",
                rollback_capable=True,
                rollback_procedure=f"Remove address object 'blocked-{ip}' from firewall",
                executed_at=datetime.utcnow(),
            )
        except httpx.HTTPError as e:
            return ActionResult(
                action_type=ActionType.BLOCK_IP,
                target=ip,
                status=ActionStatus.FAILED,
                adapter_used=f"{self.product_type}/{self.vendor}",
                evidence={"error": str(e)},
            )

    async def _unblock_ip(self, ip: str) -> ActionResult:
        """Remove an IP from the block list."""
        request_params = {
            "type": "config",
            "action": "delete",
            "xpath": f"/config/devices/entry/vsys/entry/address/entry[@name='blocked-{ip}']",
        }

        try:
            response = await self._client.post("/api/", params=request_params)
            response.raise_for_status()

            return ActionResult(
                action_type=ActionType.UNBLOCK_IP,
                target=ip,
                status=ActionStatus.SUCCESS,
                adapter_used=f"{self.product_type}/{self.vendor}",
                executed_at=datetime.utcnow(),
            )
        except httpx.HTTPError as e:
            return ActionResult(
                action_type=ActionType.UNBLOCK_IP,
                target=ip,
                status=ActionStatus.FAILED,
                evidence={"error": str(e)},
            )

    async def health_check(self) -> HealthStatus:
        """Check PAN-OS API connectivity."""
        try:
            response = await self._client.get("/api/", params={"type": "version"})
            response.raise_for_status()
            return HealthStatus(state=HealthState.HEALTHY, message="PAN-OS API reachable")
        except Exception as e:
            return HealthStatus(state=HealthState.UNAVAILABLE, message=str(e))

    def _parse_panos_response(self, xml_text: str) -> list[dict[str, Any]]:
        """Parse PAN-OS XML response into list of dicts (simplified)."""
        # In production, use proper XML parsing
        return []

    @staticmethod
    def _map_severity(panos_severity: str) -> Severity:
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFO,
        }
        return mapping.get(panos_severity.lower(), Severity.MEDIUM)
