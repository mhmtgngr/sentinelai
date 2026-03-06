"""SIEM adapters (Wazuh, Splunk)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class WazuhAdapter(BaseSecurityAdapter):
    product_type = "siem"
    vendor = "wazuh"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._user = config.get("api_user") or os.getenv("WAZUH_API_USER", "wazuh")
        self._password = config.get("api_password") or os.getenv("WAZUH_API_PASSWORD", "")
        self._token: str = ""
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.endpoint,
            verify=self.config.get("verify_ssl", False),
            timeout=30.0,
        )
        # Get JWT token
        resp = await self._client.post(
            "/security/user/authenticate",
            auth=(self._user, self._password),
        )
        resp.raise_for_status()
        self._token = resp.json().get("data", {}).get("token", "")
        self._client.headers["Authorization"] = f"Bearer {self._token}"

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        try:
            params: dict[str, Any] = {"limit": 500, "sort": "-timestamp"}
            if since:
                params["search"] = since.strftime("%Y-%m-%d %H:%M:%S")
            resp = await self._client.get("/alerts", params=params)
            resp.raise_for_status()
            return self._parse_alerts(resp.json())
        except Exception:
            self.logger.exception("Error fetching Wazuh alerts")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/manager/status")
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("affected_items", [{}])[0]
                if data.get("wazuh-analysisd") == "running":
                    return HealthStatus.HEALTHY
                return HealthStatus.DEGRADED
            return HealthStatus.UNHEALTHY
        except Exception:
            return HealthStatus.UNHEALTHY

    async def run_rootcheck(self, agent_id: str) -> ActionResult:
        """Trigger a rootcheck scan on a Wazuh agent."""
        if not self._client:
            return ActionResult(success=False, action="rootcheck", message="Not connected")
        try:
            resp = await self._client.put(f"/rootcheck/{agent_id}")
            return ActionResult(
                success=resp.status_code == 200,
                action="rootcheck",
                message=f"Rootcheck started on agent {agent_id}",
            )
        except Exception as e:
            return ActionResult(success=False, action="rootcheck", message=str(e))

    def _parse_alerts(self, data: dict) -> list[dict[str, Any]]:
        events = []
        items = data.get("data", {}).get("affected_items", [])
        for alert in items:
            rule = alert.get("rule", {})
            agent = alert.get("agent", {})
            events.append(self._build_event(
                alert,
                event_type="alert",
                severity=self._map_level(rule.get("level", 0)),
                description=rule.get("description", ""),
                source_ip=alert.get("data", {}).get("srcip", ""),
                rule_id=str(rule.get("id", "")),
                rule_name=rule.get("description", ""),
                mitre_tactic=",".join(rule.get("mitre", {}).get("tactic", [])),
                mitre_technique=",".join(rule.get("mitre", {}).get("id", [])),
            ))
        return events

    @staticmethod
    def _map_level(level: int) -> str:
        if level >= 12:
            return "critical"
        if level >= 9:
            return "high"
        if level >= 5:
            return "medium"
        if level >= 3:
            return "low"
        return "info"


class SplunkAdapter(BaseSecurityAdapter):
    product_type = "siem"
    vendor = "splunk"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._hec_token = config.get("hec_token") or os.getenv("SPLUNK_HEC_TOKEN", "")
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.endpoint,
            headers={"Authorization": f"Bearer {self._hec_token}"},
            verify=self.config.get("verify_ssl", False),
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        try:
            search_query = 'search index=main sourcetype="syslog" | head 100'
            if since:
                search_query += f' earliest="{since.strftime("%m/%d/%Y:%H:%M:%S")}"'
            resp = await self._client.post(
                "/services/search/jobs/export",
                data={"search": search_query, "output_mode": "json"},
            )
            resp.raise_for_status()
            return self._parse_results(resp.json())
        except Exception:
            self.logger.exception("Error fetching Splunk events")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/services/server/health/splunkd", params={"output_mode": "json"})
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    def _parse_results(self, data: dict) -> list[dict[str, Any]]:
        events = []
        for result in data.get("results", []):
            events.append(self._build_event(
                result,
                event_type="siem_event",
                severity=result.get("severity", "info"),
                description=result.get("_raw", ""),
                source_ip=result.get("src_ip", ""),
                destination_ip=result.get("dest_ip", ""),
            ))
        return events
