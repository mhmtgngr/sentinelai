"""WAF Adapter — Cloudflare WAF integration.

Provides event ingestion and IP blocking via Cloudflare API v4.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from src.core.models import (
    ActionResult, ActionStatus, ActionType, HealthState, HealthStatus,
    SecurityEvent, Severity,
)
from src.integrations.base_adapter import BaseSecurityAdapter

logger = logging.getLogger(__name__)


class WAFAdapter(BaseSecurityAdapter):
    product_type = "waf"
    vendor = "cloudflare"

    def __init__(self, endpoint: str, api_token: str = "", zone_id: str = "", **kwargs: Any) -> None:
        super().__init__(endpoint, **kwargs)
        self._zone_id = zone_id
        self._client = httpx.AsyncClient(
            base_url="https://api.cloudflare.com/client/v4",
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime) -> list[SecurityEvent]:
        response = await self._client.get(
            f"/zones/{self._zone_id}/security/events",
            params={"since": since.isoformat()},
        )
        response.raise_for_status()
        data = response.json()

        events = []
        for entry in data.get("result", []):
            events.append(SecurityEvent(
                source_adapter=f"{self.product_type}/{self.vendor}",
                event_type=entry.get("action", "block"),
                severity=Severity.MEDIUM,
                raw_payload=entry,
                normalized={"source_ip": entry.get("clientIP"), "uri": entry.get("clientRequestPath")},
                affected_assets=[entry.get("clientIP", "")],
            ))
        return events

    async def execute_action(self, action_type: ActionType, target: str, params: dict[str, Any] | None = None) -> ActionResult:
        if action_type == ActionType.BLOCK_IP:
            try:
                response = await self._client.post(
                    f"/zones/{self._zone_id}/firewall/access_rules/rules",
                    json={"mode": "block", "configuration": {"target": "ip", "value": target}, "notes": "Sentinel-AI block"},
                )
                response.raise_for_status()
                rule_id = response.json().get("result", {}).get("id", "")
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.SUCCESS, adapter_used=f"{self.product_type}/{self.vendor}", rollback_capable=True, rollback_procedure=f"Delete WAF rule {rule_id}", executed_at=datetime.utcnow())
            except httpx.HTTPError as e:
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, evidence={"error": str(e)})

        return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, evidence={"error": "unsupported"})

    async def health_check(self) -> HealthStatus:
        try:
            response = await self._client.get("/user/tokens/verify")
            response.raise_for_status()
            return HealthStatus(state=HealthState.HEALTHY, message="Cloudflare API reachable")
        except Exception as e:
            return HealthStatus(state=HealthState.UNAVAILABLE, message=str(e))
