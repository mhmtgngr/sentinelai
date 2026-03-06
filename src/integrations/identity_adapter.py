"""Identity provider adapters (Entra ID, Okta)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class EntraIDAdapter(BaseSecurityAdapter):
    product_type = "identity"
    vendor = "entra_id"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._tenant_id = config.get("tenant_id") or os.getenv("ENTRA_TENANT_ID", "")
        self._client_id = config.get("client_id") or os.getenv("ENTRA_CLIENT_ID", "")
        self._client_secret = config.get("client_secret") or os.getenv("ENTRA_CLIENT_SECRET", "")
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
        if not self._client:
            return []
        try:
            # Fetch risky sign-ins
            resp = await self._client.get("/identityProtection/riskyUsers")
            resp.raise_for_status()
            return self._parse_risky_users(resp.json())
        except Exception:
            self.logger.exception("Error fetching Entra ID events")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/organization")
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def disable_user(self, user_id: str, reason: str) -> ActionResult:
        """Disable a user account in Entra ID."""
        if not self._client:
            return ActionResult(success=False, action="disable_user", message="Not connected")
        try:
            resp = await self._client.patch(
                f"/users/{user_id}",
                json={"accountEnabled": False},
            )
            return ActionResult(
                success=resp.status_code == 204,
                action="disable_user",
                message=f"Disabled user {user_id}: {reason}",
            )
        except Exception as e:
            return ActionResult(success=False, action="disable_user", message=str(e))

    async def revoke_sessions(self, user_id: str) -> ActionResult:
        """Revoke all active sessions for a user."""
        if not self._client:
            return ActionResult(success=False, action="revoke_sessions", message="Not connected")
        try:
            resp = await self._client.post(f"/users/{user_id}/revokeSignInSessions")
            return ActionResult(
                success=resp.status_code == 200,
                action="revoke_sessions",
                message=f"Revoked sessions for user {user_id}",
            )
        except Exception as e:
            return ActionResult(success=False, action="revoke_sessions", message=str(e))

    def _parse_risky_users(self, data: dict) -> list[dict[str, Any]]:
        events = []
        for user in data.get("value", []):
            if user.get("riskLevel") != "none":
                events.append(self._build_event(
                    user,
                    event_type="risky_user",
                    severity=self._map_risk_level(user.get("riskLevel", "")),
                    description=f"Risky user: {user.get('userDisplayName', '')} - {user.get('riskDetail', '')}",
                ))
        return events

    @staticmethod
    def _map_risk_level(level: str) -> str:
        mapping = {"high": "high", "medium": "medium", "low": "low", "none": "info"}
        return mapping.get(level.lower(), "info")


class OktaAdapter(BaseSecurityAdapter):
    product_type = "identity"
    vendor = "okta"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_token = config.get("api_token") or os.getenv("OKTA_API_TOKEN", "")
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.endpoint,
            headers={"Authorization": f"SSWS {self._api_token}"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        try:
            params: dict[str, Any] = {"limit": 100, "sortOrder": "DESCENDING"}
            if since:
                params["since"] = since.isoformat()
            resp = await self._client.get("/api/v1/logs", params=params)
            resp.raise_for_status()
            return self._parse_logs(resp.json())
        except Exception:
            self.logger.exception("Error fetching Okta events")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/api/v1/org")
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    def _parse_logs(self, data: list) -> list[dict[str, Any]]:
        events = []
        for entry in data:
            severity = "info"
            outcome = entry.get("outcome", {}).get("result", "")
            if outcome == "FAILURE":
                severity = "medium"
            if entry.get("eventType", "").startswith("policy.evaluate_sign_on"):
                severity = "high" if outcome == "FAILURE" else "low"
            events.append(self._build_event(
                entry,
                event_type=entry.get("eventType", ""),
                severity=severity,
                description=entry.get("displayMessage", ""),
                source_ip=entry.get("client", {}).get("ipAddress", ""),
            ))
        return events
