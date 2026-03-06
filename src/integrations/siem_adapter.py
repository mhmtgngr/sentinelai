"""SIEM adapter — IBM QRadar (on-premises)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class QRadarAdapter(BaseSecurityAdapter):
    """IBM QRadar on-prem SIEM adapter.

    Connects via the QRadar REST API to pull offenses, events, and manage rules.
    Requires a QRadar API token with appropriate permissions.
    """

    product_type = "siem"
    vendor = "qradar"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_token = config.get("api_token") or os.getenv("QRADAR_API_TOKEN", "")
        self._api_version = config.get("api_version", "19.0")
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.endpoint,
            headers={
                "SEC": self._api_token,
                "Version": self._api_version,
                "Accept": "application/json",
            },
            verify=self.config.get("verify_ssl", False),
            timeout=60.0,
        )
        # Validate token by fetching system info
        resp = await self._client.get("/api/system/about")
        resp.raise_for_status()
        self.logger.info("Connected to QRadar v%s", resp.json().get("external_version", "unknown"))

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Fetch open/active offenses from QRadar."""
        if not self._client:
            return []
        try:
            params: dict[str, Any] = {}
            filter_parts = ["status=OPEN"]
            if since:
                epoch_ms = int(since.timestamp() * 1000)
                filter_parts.append(f"start_time > {epoch_ms}")
            params["filter"] = " and ".join(filter_parts)
            params["fields"] = (
                "id,description,magnitude,severity,credibility,relevance,"
                "offense_type,offense_source,source_network,destination_networks,"
                "categories,start_time,last_updated_time,event_count,flow_count,"
                "assigned_to,status,closing_reason_id,rules"
            )

            resp = await self._client.get("/api/siem/offenses", params=params)
            resp.raise_for_status()
            return self._parse_offenses(resp.json())
        except Exception:
            self.logger.exception("Error fetching QRadar offenses")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/api/system/about")
            if resp.status_code == 200:
                return HealthStatus.HEALTHY
            return HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def get_offense_events(self, offense_id: int, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch events associated with a specific offense via AQL."""
        if not self._client:
            return []
        try:
            aql = (
                f"SELECT * FROM events WHERE INOFFENSE({offense_id}) "
                f"ORDER BY starttime DESC LIMIT {limit}"
            )
            return await self.run_aql_query(aql)
        except Exception:
            self.logger.exception("Error fetching offense events for offense %d", offense_id)
            return []

    async def run_aql_query(self, aql: str) -> list[dict[str, Any]]:
        """Execute an arbitrary AQL query against QRadar."""
        if not self._client:
            return []
        try:
            import asyncio
            resp = await self._client.post(
                "/api/ariel/searches",
                params={"query_expression": aql},
            )
            resp.raise_for_status()
            search_id = resp.json().get("search_id", "")

            for _ in range(30):
                status_resp = await self._client.get(f"/api/ariel/searches/{search_id}")
                status_resp.raise_for_status()
                if status_resp.json().get("status") == "COMPLETED":
                    results_resp = await self._client.get(
                        f"/api/ariel/searches/{search_id}/results"
                    )
                    results_resp.raise_for_status()
                    return results_resp.json().get("events", [])
                await asyncio.sleep(2)
            return []
        except Exception:
            self.logger.exception("Error running AQL query")
            return []

    async def close_offense(self, offense_id: int, closing_reason_id: int, note: str = "") -> ActionResult:
        """Close an offense in QRadar."""
        if not self._client:
            return ActionResult(success=False, action="close_offense", message="Not connected")
        try:
            resp = await self._client.post(
                f"/api/siem/offenses/{offense_id}",
                params={
                    "status": "CLOSED",
                    "closing_reason_id": str(closing_reason_id),
                },
            )
            if note:
                await self._client.post(
                    f"/api/siem/offenses/{offense_id}/notes",
                    params={"note_text": note},
                )
            return ActionResult(
                success=resp.status_code == 200,
                action="close_offense",
                message=f"Closed offense {offense_id}",
            )
        except Exception as e:
            return ActionResult(success=False, action="close_offense", message=str(e))

    async def add_offense_note(self, offense_id: int, note: str) -> ActionResult:
        """Add a note to an offense."""
        if not self._client:
            return ActionResult(success=False, action="add_note", message="Not connected")
        try:
            resp = await self._client.post(
                f"/api/siem/offenses/{offense_id}/notes",
                params={"note_text": note},
            )
            return ActionResult(
                success=resp.status_code in (200, 201),
                action="add_note",
                message=f"Added note to offense {offense_id}",
            )
        except Exception as e:
            return ActionResult(success=False, action="add_note", message=str(e))

    async def get_reference_set(self, name: str) -> list[str]:
        """Get values from a QRadar reference set (useful for IOC lists)."""
        if not self._client:
            return []
        try:
            resp = await self._client.get(f"/api/reference_data/sets/{name}")
            resp.raise_for_status()
            return [item.get("value", "") for item in resp.json().get("data", [])]
        except Exception:
            self.logger.exception("Error fetching reference set: %s", name)
            return []

    async def add_to_reference_set(self, name: str, value: str) -> ActionResult:
        """Add a value to a QRadar reference set (e.g., blocked IPs)."""
        if not self._client:
            return ActionResult(success=False, action="add_to_reference_set", message="Not connected")
        try:
            resp = await self._client.post(
                f"/api/reference_data/sets/{name}",
                params={"value": value},
            )
            return ActionResult(
                success=resp.status_code in (200, 201),
                action="add_to_reference_set",
                message=f"Added {value} to reference set {name}",
            )
        except Exception as e:
            return ActionResult(success=False, action="add_to_reference_set", message=str(e))

    def _parse_offenses(self, offenses: list[dict]) -> list[dict[str, Any]]:
        events = []
        for offense in offenses:
            categories = offense.get("categories", [])
            events.append(self._build_event(
                offense,
                event_type="offense",
                severity=self._map_magnitude(offense.get("magnitude", 0)),
                description=offense.get("description", ""),
                source_ip=offense.get("offense_source", ""),
                rule_id=str(offense.get("id", "")),
                rule_name=", ".join(
                    r.get("name", "") for r in (offense.get("rules") or [])
                ),
                mitre_tactic=self._infer_tactic(categories),
            ))
        return events

    @staticmethod
    def _map_magnitude(magnitude: int) -> str:
        """Map QRadar offense magnitude (1-10) to severity."""
        if magnitude >= 8:
            return "critical"
        if magnitude >= 6:
            return "high"
        if magnitude >= 4:
            return "medium"
        if magnitude >= 2:
            return "low"
        return "info"

    @staticmethod
    def _infer_tactic(categories: list[str]) -> str:
        """Infer MITRE tactic from QRadar offense categories."""
        category_str = " ".join(categories).lower()
        if any(kw in category_str for kw in ["recon", "scan", "probe"]):
            return "Reconnaissance"
        if any(kw in category_str for kw in ["exploit", "overflow", "injection"]):
            return "Initial Access"
        if any(kw in category_str for kw in ["malware", "trojan", "ransomware"]):
            return "Execution"
        if any(kw in category_str for kw in ["privilege", "escalat"]):
            return "Privilege Escalation"
        if any(kw in category_str for kw in ["lateral", "pivot"]):
            return "Lateral Movement"
        if any(kw in category_str for kw in ["exfil", "data loss", "leak"]):
            return "Exfiltration"
        if any(kw in category_str for kw in ["denial", "dos"]):
            return "Impact"
        return ""
