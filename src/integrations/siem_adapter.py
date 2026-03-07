"""SIEM Adapter — Wazuh integration.

Read-only adapter for alert retrieval and log search via Wazuh REST API.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from src.core.models import (
    ActionResult, ActionStatus, ActionType, HealthState, HealthStatus,
    IOC, SecurityEvent, Severity,
)
from src.integrations.base_adapter import BaseSecurityAdapter

logger = logging.getLogger(__name__)

WAZUH_SEVERITY_MAP = {1: Severity.LOW, 2: Severity.LOW, 3: Severity.LOW, 4: Severity.LOW, 5: Severity.MEDIUM, 6: Severity.MEDIUM, 7: Severity.MEDIUM, 8: Severity.HIGH, 9: Severity.HIGH, 10: Severity.HIGH, 11: Severity.HIGH, 12: Severity.CRITICAL, 13: Severity.CRITICAL, 14: Severity.CRITICAL, 15: Severity.CRITICAL}


class SIEMAdapter(BaseSecurityAdapter):
    product_type = "siem"
    vendor = "wazuh"

    def __init__(self, endpoint: str, username: str = "", password: str = "", **kwargs: Any) -> None:
        super().__init__(endpoint, **kwargs)
        self._client = httpx.AsyncClient(base_url=endpoint, auth=(username, password), verify=False, timeout=30.0)
        self._token: str | None = None

    async def _authenticate(self) -> str:
        response = await self._client.post("/security/user/authenticate")
        response.raise_for_status()
        self._token = response.json().get("data", {}).get("token", "")
        self._client.headers["Authorization"] = f"Bearer {self._token}"
        return self._token

    async def get_events(self, since: datetime) -> list[SecurityEvent]:
        if not self._token:
            await self._authenticate()

        response = await self._client.get("/alerts", params={"pretty": "true", "limit": 100, "sort": "-timestamp"})
        response.raise_for_status()

        events = []
        for item in response.json().get("data", {}).get("affected_items", []):
            rule = item.get("rule", {})
            agent = item.get("agent", {})
            data = item.get("data", {})

            iocs = []
            if data.get("srcip"):
                iocs.append(IOC(type="ip", value=data["srcip"], source="wazuh"))

            events.append(SecurityEvent(
                source_adapter=f"{self.product_type}/{self.vendor}",
                event_type=rule.get("description", "unknown"),
                severity=WAZUH_SEVERITY_MAP.get(rule.get("level", 3), Severity.MEDIUM),
                raw_payload=item,
                normalized={"source_ip": data.get("srcip"), "target_host": agent.get("name"), "rule_id": rule.get("id")},
                mitre_attack=[g.get("id", "") for g in rule.get("mitre", {}).get("technique", [])],
                affected_assets=[agent.get("name", "")],
                iocs=iocs,
            ))
        return events

    async def execute_action(self, action_type: ActionType, target: str, params: dict[str, Any] | None = None) -> ActionResult:
        return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, adapter_used=f"{self.product_type}/{self.vendor}", evidence={"error": "SIEM adapter is read-only"})

    async def health_check(self) -> HealthStatus:
        try:
            response = await self._client.get("/manager/info")
            response.raise_for_status()
            return HealthStatus(state=HealthState.HEALTHY, message="Wazuh API reachable")
        except Exception as e:
            return HealthStatus(state=HealthState.UNAVAILABLE, message=str(e))
