"""EDR Adapter — CrowdStrike Falcon integration.

Endpoint detection, host containment, and file quarantine
via CrowdStrike Falcon API.
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


class EDRAdapter(BaseSecurityAdapter):
    product_type = "edr"
    vendor = "crowdstrike"

    def __init__(self, endpoint: str, client_id: str = "", client_secret: str = "", **kwargs: Any) -> None:
        super().__init__(endpoint, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret
        self._client = httpx.AsyncClient(base_url="https://api.crowdstrike.com", timeout=30.0)
        self._token: str | None = None

    async def _authenticate(self) -> str:
        response = await self._client.post("/oauth2/token", data={"client_id": self._client_id, "client_secret": self._client_secret})
        response.raise_for_status()
        self._token = response.json()["access_token"]
        self._client.headers["Authorization"] = f"Bearer {self._token}"
        return self._token

    async def get_events(self, since: datetime) -> list[SecurityEvent]:
        if not self._token:
            await self._authenticate()

        response = await self._client.get("/detects/queries/detects/v1", params={"filter": f"created_timestamp:>'{since.isoformat()}Z'", "limit": 100})
        response.raise_for_status()
        detect_ids = response.json().get("resources", [])

        if not detect_ids:
            return []

        detail_response = await self._client.post("/detects/entities/summaries/GET/v1", json={"ids": detect_ids[:100]})
        detail_response.raise_for_status()

        events = []
        for detection in detail_response.json().get("resources", []):
            device = detection.get("device", {})
            behaviors = detection.get("behaviors", [{}])
            behavior = behaviors[0] if behaviors else {}

            iocs = []
            if behavior.get("sha256"):
                iocs.append(IOC(type="hash", value=behavior["sha256"], source="crowdstrike"))

            events.append(SecurityEvent(
                source_adapter=f"{self.product_type}/{self.vendor}",
                event_type=behavior.get("tactic", "unknown"),
                severity=self._map_severity(detection.get("max_severity_displayname", "Medium")),
                raw_payload=detection,
                normalized={"hostname": device.get("hostname"), "filename": behavior.get("filename"), "cmdline": behavior.get("cmdline")},
                mitre_attack=[behavior.get("technique_id", "")] if behavior.get("technique_id") else [],
                affected_assets=[device.get("hostname", "")],
                iocs=iocs,
            ))
        return events

    async def execute_action(self, action_type: ActionType, target: str, params: dict[str, Any] | None = None) -> ActionResult:
        if not self._token:
            await self._authenticate()

        if action_type == ActionType.ISOLATE_HOST:
            try:
                response = await self._client.post("/devices/entities/devices-actions/v2", params={"action_name": "contain"}, json={"ids": [target]})
                response.raise_for_status()
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.SUCCESS, adapter_used=f"{self.product_type}/{self.vendor}", rollback_capable=True, rollback_procedure=f"Lift containment on host {target}", executed_at=datetime.utcnow())
            except httpx.HTTPError as e:
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, evidence={"error": str(e)})

        if action_type == ActionType.UNISOLATE_HOST:
            try:
                response = await self._client.post("/devices/entities/devices-actions/v2", params={"action_name": "lift_containment"}, json={"ids": [target]})
                response.raise_for_status()
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.SUCCESS, adapter_used=f"{self.product_type}/{self.vendor}", executed_at=datetime.utcnow())
            except httpx.HTTPError as e:
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, evidence={"error": str(e)})

        return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, evidence={"error": "unsupported"})

    async def health_check(self) -> HealthStatus:
        try:
            if not self._token:
                await self._authenticate()
            response = await self._client.get("/sensors/queries/sensors/v1", params={"limit": 1})
            response.raise_for_status()
            return HealthStatus(state=HealthState.HEALTHY, message="Falcon API reachable")
        except Exception as e:
            return HealthStatus(state=HealthState.UNAVAILABLE, message=str(e))

    @staticmethod
    def _map_severity(cs_severity: str) -> Severity:
        return {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "informational": Severity.INFO}.get(cs_severity.lower(), Severity.MEDIUM)
