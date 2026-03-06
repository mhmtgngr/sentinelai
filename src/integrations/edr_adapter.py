"""EDR adapters (CrowdStrike, SentinelOne)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class CrowdStrikeAdapter(BaseSecurityAdapter):
    product_type = "edr"
    vendor = "crowdstrike"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._client_id = config.get("client_id") or os.getenv("CROWDSTRIKE_CLIENT_ID", "")
        self._client_secret = config.get("client_secret") or os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
        self._token: str = ""
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        base = self.endpoint or "https://api.crowdstrike.com"
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{base}/oauth2/token",
                data={"client_id": self._client_id, "client_secret": self._client_secret},
            )
            resp.raise_for_status()
            self._token = resp.json()["access_token"]
        self._client = httpx.AsyncClient(
            base_url=base,
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        try:
            params: dict[str, str] = {"sort": "last_behavior|desc", "limit": "100"}
            if since:
                params["filter"] = f"last_behavior:>'{since.isoformat()}'"
            resp = await self._client.get("/detects/queries/detects/v1", params=params)
            resp.raise_for_status()
            detect_ids = resp.json().get("resources", [])
            if not detect_ids:
                return []
            # Get detection details
            detail_resp = await self._client.post(
                "/detects/entities/summaries/GET/v1",
                json={"ids": detect_ids[:100]},
            )
            detail_resp.raise_for_status()
            return self._parse_detections(detail_resp.json())
        except Exception:
            self.logger.exception("Error fetching CrowdStrike detections")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/sensors/queries/sensors/v1", params={"limit": "1"})
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def isolate_host(self, device_id: str, reason: str) -> ActionResult:
        """Network-contain a host via CrowdStrike."""
        if not self._client:
            return ActionResult(success=False, action="isolate_host", message="Not connected")
        try:
            resp = await self._client.post(
                "/devices/entities/devices-actions/v2",
                params={"action_name": "contain"},
                json={"ids": [device_id]},
            )
            return ActionResult(
                success=resp.status_code == 202,
                action="isolate_host",
                message=f"Isolated host {device_id}: {reason}",
            )
        except Exception as e:
            return ActionResult(success=False, action="isolate_host", message=str(e))

    def _parse_detections(self, data: dict) -> list[dict[str, Any]]:
        events = []
        for det in data.get("resources", []):
            behaviors = det.get("behaviors", [{}])
            behavior = behaviors[0] if behaviors else {}
            events.append(self._build_event(
                det,
                event_type="detection",
                severity=self._map_severity(det.get("max_severity_displayname", "")),
                description=behavior.get("description", det.get("description", "")),
                source_ip=behavior.get("local_ip", ""),
                mitre_tactic=behavior.get("tactic", ""),
                mitre_technique=behavior.get("technique", ""),
            ))
        return events

    @staticmethod
    def _map_severity(display_name: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        return mapping.get(display_name.lower(), "info")


class SentinelOneAdapter(BaseSecurityAdapter):
    product_type = "edr"
    vendor = "sentinelone"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_token = config.get("api_token") or os.getenv("SENTINELONE_API_TOKEN", "")
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.endpoint,
            headers={"Authorization": f"APIToken {self._api_token}"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        try:
            params: dict[str, Any] = {"limit": 100, "sortOrder": "desc"}
            if since:
                params["createdAt__gte"] = since.isoformat()
            resp = await self._client.get("/web/api/v2.1/threats", params=params)
            resp.raise_for_status()
            return self._parse_threats(resp.json())
        except Exception:
            self.logger.exception("Error fetching SentinelOne threats")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/web/api/v2.1/system/status")
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def isolate_host(self, agent_id: str, reason: str) -> ActionResult:
        if not self._client:
            return ActionResult(success=False, action="isolate_host", message="Not connected")
        try:
            resp = await self._client.post(
                "/web/api/v2.1/agents/actions/disconnect",
                json={"filter": {"ids": [agent_id]}},
            )
            return ActionResult(
                success=resp.status_code == 200,
                action="isolate_host",
                message=f"Isolated agent {agent_id}: {reason}",
            )
        except Exception as e:
            return ActionResult(success=False, action="isolate_host", message=str(e))

    def _parse_threats(self, data: dict) -> list[dict[str, Any]]:
        events = []
        for threat in data.get("data", []):
            ti = threat.get("threatInfo", {})
            events.append(self._build_event(
                threat,
                event_type="threat",
                severity=self._map_confidence(ti.get("confidenceLevel", "")),
                description=ti.get("threatName", ""),
                source_ip=threat.get("agentDetectionInfo", {}).get("agentIpV4", ""),
            ))
        return events

    @staticmethod
    def _map_confidence(level: str) -> str:
        mapping = {"malicious": "critical", "suspicious": "high", "n/a": "medium"}
        return mapping.get(level.lower(), "info")
