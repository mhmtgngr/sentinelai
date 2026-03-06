"""Microsoft Defender for Endpoint / XDR adapter."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class DefenderXDRAdapter(BaseSecurityAdapter):
    """Microsoft Defender for Endpoint adapter.

    Uses the Microsoft 365 Defender API (via Microsoft Graph Security API)
    to pull alerts, incidents, and execute response actions.
    Requires an Entra ID app registration with SecurityAlert.Read.All,
    SecurityIncident.ReadWrite.All, Machine.Isolate, etc.
    """

    product_type = "edr"
    vendor = "defender_xdr"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._tenant_id = config.get("tenant_id") or os.getenv("DEFENDER_TENANT_ID", "")
        self._client_id = config.get("client_id") or os.getenv("DEFENDER_CLIENT_ID", "")
        self._client_secret = config.get("client_secret") or os.getenv("DEFENDER_CLIENT_SECRET", "")
        self._token: str = ""
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            self._token = resp.json()["access_token"]

        self._client = httpx.AsyncClient(
            base_url="https://graph.microsoft.com/v1.0",
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Fetch alerts from Microsoft 365 Defender."""
        if not self._client:
            return []
        try:
            params: dict[str, str] = {"$top": "100", "$orderby": "createdDateTime desc"}
            if since:
                params["$filter"] = f"createdDateTime ge {since.isoformat()}Z"
            resp = await self._client.get("/security/alerts_v2", params=params)
            resp.raise_for_status()
            return self._parse_alerts(resp.json())
        except Exception:
            self.logger.exception("Error fetching Defender alerts")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/security/alerts_v2", params={"$top": "1"})
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def get_incidents(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Fetch incidents from Microsoft 365 Defender."""
        if not self._client:
            return []
        try:
            params: dict[str, str] = {"$top": "50", "$orderby": "createdDateTime desc"}
            if since:
                params["$filter"] = f"createdDateTime ge {since.isoformat()}Z"
            resp = await self._client.get("/security/incidents", params=params)
            resp.raise_for_status()
            return resp.json().get("value", [])
        except Exception:
            self.logger.exception("Error fetching Defender incidents")
            return []

    async def isolate_host(self, machine_id: str, reason: str) -> ActionResult:
        """Isolate a device via Microsoft Defender for Endpoint."""
        if not self._client:
            return ActionResult(success=False, action="isolate_host", message="Not connected")
        try:
            # Uses the Defender for Endpoint API (different base URL)
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=30.0,
            ) as client:
                resp = await client.post(
                    f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
                    json={
                        "Comment": f"Sentinel-AI: {reason}",
                        "IsolationType": "Full",
                    },
                )
                return ActionResult(
                    success=resp.status_code in (200, 201),
                    action="isolate_host",
                    message=f"Isolated machine {machine_id}: {reason}",
                    data=resp.json() if resp.status_code in (200, 201) else {},
                )
        except Exception as e:
            return ActionResult(success=False, action="isolate_host", message=str(e))

    async def unisolate_host(self, machine_id: str, reason: str) -> ActionResult:
        """Release a device from isolation."""
        if not self._client:
            return ActionResult(success=False, action="unisolate_host", message="Not connected")
        try:
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=30.0,
            ) as client:
                resp = await client.post(
                    f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/unisolate",
                    json={"Comment": f"Sentinel-AI: {reason}"},
                )
                return ActionResult(
                    success=resp.status_code in (200, 201),
                    action="unisolate_host",
                    message=f"Released machine {machine_id} from isolation: {reason}",
                )
        except Exception as e:
            return ActionResult(success=False, action="unisolate_host", message=str(e))

    async def run_antivirus_scan(self, machine_id: str, scan_type: str = "Quick") -> ActionResult:
        """Trigger AV scan on a device (Quick or Full)."""
        if not self._client:
            return ActionResult(success=False, action="av_scan", message="Not connected")
        try:
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=30.0,
            ) as client:
                resp = await client.post(
                    f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/runAntiVirusScan",
                    json={
                        "Comment": "Sentinel-AI initiated scan",
                        "ScanType": scan_type,
                    },
                )
                return ActionResult(
                    success=resp.status_code in (200, 201),
                    action="av_scan",
                    message=f"{scan_type} AV scan triggered on {machine_id}",
                )
        except Exception as e:
            return ActionResult(success=False, action="av_scan", message=str(e))

    async def update_incident(self, incident_id: str, status: str, classification: str = "", determination: str = "") -> ActionResult:
        """Update a Defender incident's status/classification."""
        if not self._client:
            return ActionResult(success=False, action="update_incident", message="Not connected")
        try:
            body: dict[str, str] = {"status": status}
            if classification:
                body["classification"] = classification
            if determination:
                body["determination"] = determination
            resp = await self._client.patch(
                f"/security/incidents/{incident_id}",
                json=body,
            )
            return ActionResult(
                success=resp.status_code in (200, 204),
                action="update_incident",
                message=f"Updated incident {incident_id} to {status}",
            )
        except Exception as e:
            return ActionResult(success=False, action="update_incident", message=str(e))

    async def advanced_hunting(self, kql_query: str) -> list[dict[str, Any]]:
        """Run an Advanced Hunting (KQL) query."""
        if not self._client:
            return []
        try:
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=120.0,
            ) as client:
                resp = await client.post(
                    "https://api.securitycenter.microsoft.com/api/advancedqueries/run",
                    json={"Query": kql_query},
                )
                resp.raise_for_status()
                return resp.json().get("Results", [])
        except Exception:
            self.logger.exception("Error running Advanced Hunting query")
            return []

    def _parse_alerts(self, data: dict) -> list[dict[str, Any]]:
        events = []
        for alert in data.get("value", []):
            mitre = alert.get("mitreTechniques", [])
            events.append(self._build_event(
                alert,
                event_type="defender_alert",
                severity=alert.get("severity", "info").lower(),
                description=alert.get("title", ""),
                source_ip=self._extract_ip(alert),
                rule_id=alert.get("detectorId", ""),
                rule_name=alert.get("detectionSource", ""),
                mitre_technique=", ".join(mitre),
                mitre_tactic=alert.get("category", ""),
            ))
        return events

    @staticmethod
    def _extract_ip(alert: dict) -> str:
        evidence = alert.get("evidence", [])
        for e in evidence:
            ip = e.get("ipAddress", "")
            if ip:
                return ip
        return ""
