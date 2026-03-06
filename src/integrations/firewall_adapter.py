"""Firewall adapter — Palo Alto Networks."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class PaloAltoAdapter(BaseSecurityAdapter):
    product_type = "firewall"
    vendor = "paloalto"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_key = config.get("api_key") or os.getenv("PALOALTO_API_KEY", "")
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.endpoint,
            headers={"X-PAN-KEY": self._api_key},
            verify=self.config.get("verify_ssl", True),
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        try:
            params = {"type": "log", "log-type": "threat"}
            if since:
                params["query"] = f"(receive_time geq '{since.strftime('%Y/%m/%d %H:%M:%S')}')"
            resp = await self._client.get("/api/", params=params)
            resp.raise_for_status()
            return self._parse_threat_logs(resp.json())
        except Exception:
            self.logger.exception("Error fetching PaloAlto events")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/api/", params={"type": "op", "cmd": "<show><system><info></info></system></show>"})
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def block_ip(self, ip: str, reason: str) -> ActionResult:
        """Block an IP address via dynamic address group."""
        if not self._client:
            return ActionResult(success=False, action="block_ip", message="Not connected")
        try:
            # Register IP as a tag in DAG
            payload = {
                "type": "user-id",
                "cmd": f"<uid-message><payload><register><entry ip=\"{ip}\"><tag><member>sentinel-blocked</member></tag></entry></register></payload></uid-message>",
            }
            resp = await self._client.post("/api/", data=payload)
            return ActionResult(
                success=resp.status_code == 200,
                action="block_ip",
                message=f"Blocked {ip}: {reason}",
                data={"ip": ip},
            )
        except Exception as e:
            return ActionResult(success=False, action="block_ip", message=str(e))

    def _parse_threat_logs(self, data: dict) -> list[dict[str, Any]]:
        events = []
        logs = data.get("response", {}).get("result", {}).get("log", {}).get("logs", {}).get("entry", [])
        if isinstance(logs, dict):
            logs = [logs]
        for log in logs:
            events.append(self._build_event(
                log,
                event_type="threat",
                severity=self._map_severity(log.get("severity", "")),
                description=log.get("threatid", ""),
                source_ip=log.get("src", ""),
                destination_ip=log.get("dst", ""),
                rule_name=log.get("rule", ""),
            ))
        return events

    @staticmethod
    def _map_severity(pan_severity: str) -> str:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
        return mapping.get(pan_severity.lower(), "info")


