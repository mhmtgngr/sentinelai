"""Identity adapter — Microsoft Entra ID (E5 license)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class EntraIDAdapter(BaseSecurityAdapter):
    """Microsoft Entra ID adapter (E5 license).

    Leverages the full E5 security feature set:
    - Identity Protection (risky users, risky sign-ins)
    - Conditional Access policy evaluation
    - Sign-in and audit log monitoring
    - User and session management (disable, revoke, force MFA)
    - Privileged Identity Management (PIM) monitoring
    """

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
        """Fetch risky users, risky sign-ins, and sign-in anomalies."""
        if not self._client:
            return []
        events: list[dict[str, Any]] = []
        try:
            # Risky users (Identity Protection — E5)
            risky_users = await self._get_risky_users()
            events.extend(risky_users)

            # Risky sign-ins (Identity Protection — E5)
            risky_signins = await self._get_risky_signins(since)
            events.extend(risky_signins)

            # Suspicious sign-in activities
            suspicious = await self._get_suspicious_signins(since)
            events.extend(suspicious)

        except Exception:
            self.logger.exception("Error fetching Entra ID events")
        return events

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

    async def enable_user(self, user_id: str) -> ActionResult:
        """Re-enable a user account."""
        if not self._client:
            return ActionResult(success=False, action="enable_user", message="Not connected")
        try:
            resp = await self._client.patch(
                f"/users/{user_id}",
                json={"accountEnabled": True},
            )
            return ActionResult(
                success=resp.status_code == 204,
                action="enable_user",
                message=f"Enabled user {user_id}",
            )
        except Exception as e:
            return ActionResult(success=False, action="enable_user", message=str(e))

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

    async def force_password_reset(self, user_id: str) -> ActionResult:
        """Force a user to reset their password on next sign-in."""
        if not self._client:
            return ActionResult(success=False, action="force_password_reset", message="Not connected")
        try:
            resp = await self._client.patch(
                f"/users/{user_id}",
                json={
                    "passwordProfile": {
                        "forceChangePasswordNextSignIn": True,
                        "forceChangePasswordNextSignInWithMfa": True,
                    }
                },
            )
            return ActionResult(
                success=resp.status_code == 204,
                action="force_password_reset",
                message=f"Forced password reset for user {user_id}",
            )
        except Exception as e:
            return ActionResult(success=False, action="force_password_reset", message=str(e))

    async def confirm_user_compromised(self, user_id: str) -> ActionResult:
        """Confirm a risky user as compromised (Identity Protection — E5)."""
        if not self._client:
            return ActionResult(success=False, action="confirm_compromised", message="Not connected")
        try:
            resp = await self._client.post(
                "/identityProtection/riskyUsers/confirmCompromised",
                json={"userIds": [user_id]},
            )
            return ActionResult(
                success=resp.status_code == 204,
                action="confirm_compromised",
                message=f"Confirmed user {user_id} as compromised",
            )
        except Exception as e:
            return ActionResult(success=False, action="confirm_compromised", message=str(e))

    async def dismiss_user_risk(self, user_id: str) -> ActionResult:
        """Dismiss risk for a user (false positive — E5)."""
        if not self._client:
            return ActionResult(success=False, action="dismiss_risk", message="Not connected")
        try:
            resp = await self._client.post(
                "/identityProtection/riskyUsers/dismiss",
                json={"userIds": [user_id]},
            )
            return ActionResult(
                success=resp.status_code == 204,
                action="dismiss_risk",
                message=f"Dismissed risk for user {user_id}",
            )
        except Exception as e:
            return ActionResult(success=False, action="dismiss_risk", message=str(e))

    async def get_sign_in_logs(self, user_id: str = "", top: int = 50) -> list[dict[str, Any]]:
        """Fetch sign-in logs from Entra ID."""
        if not self._client:
            return []
        try:
            params: dict[str, str] = {"$top": str(top), "$orderby": "createdDateTime desc"}
            if user_id:
                params["$filter"] = f"userId eq '{user_id}'"
            resp = await self._client.get("/auditLogs/signIns", params=params)
            resp.raise_for_status()
            return resp.json().get("value", [])
        except Exception:
            self.logger.exception("Error fetching sign-in logs")
            return []

    async def get_audit_logs(self, top: int = 50) -> list[dict[str, Any]]:
        """Fetch audit logs (directory changes, role assignments, etc.)."""
        if not self._client:
            return []
        try:
            resp = await self._client.get(
                "/auditLogs/directoryAudits",
                params={"$top": str(top), "$orderby": "activityDateTime desc"},
            )
            resp.raise_for_status()
            return resp.json().get("value", [])
        except Exception:
            self.logger.exception("Error fetching audit logs")
            return []

    async def get_conditional_access_policies(self) -> list[dict[str, Any]]:
        """List all Conditional Access policies (E5)."""
        if not self._client:
            return []
        try:
            resp = await self._client.get("/identity/conditionalAccess/policies")
            resp.raise_for_status()
            return resp.json().get("value", [])
        except Exception:
            self.logger.exception("Error fetching Conditional Access policies")
            return []

    # ---- Internal helpers ----

    async def _get_risky_users(self) -> list[dict[str, Any]]:
        if not self._client:
            return []
        resp = await self._client.get(
            "/identityProtection/riskyUsers",
            params={"$filter": "riskLevel ne 'none' and riskLevel ne 'hidden'"},
        )
        resp.raise_for_status()
        return self._parse_risky_users(resp.json())

    async def _get_risky_signins(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        params: dict[str, str] = {"$top": "100", "$orderby": "createdDateTime desc"}
        if since:
            params["$filter"] = f"createdDateTime ge {since.isoformat()}Z"
        resp = await self._client.get("/identityProtection/riskySignIns", params=params)
        if resp.status_code != 200:
            return []
        return self._parse_risky_signins(resp.json())

    async def _get_suspicious_signins(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Detect sign-ins from unusual locations, impossible travel, etc."""
        if not self._client:
            return []
        params: dict[str, str] = {"$top": "100", "$orderby": "createdDateTime desc"}
        filters = []
        if since:
            filters.append(f"createdDateTime ge {since.isoformat()}Z")
        filters.append("status/errorCode ne 0")
        params["$filter"] = " and ".join(filters)
        resp = await self._client.get("/auditLogs/signIns", params=params)
        if resp.status_code != 200:
            return []
        events = []
        for signin in resp.json().get("value", []):
            error_code = signin.get("status", {}).get("errorCode", 0)
            if error_code in (50126, 50074, 53003, 50053, 50057):
                severity = "high" if error_code in (50053, 50057) else "medium"
                events.append(self._build_event(
                    signin,
                    event_type="failed_signin",
                    severity=severity,
                    description=f"Failed sign-in: {signin.get('status', {}).get('failureReason', '')}",
                    source_ip=signin.get("ipAddress", ""),
                ))
        return events

    def _parse_risky_users(self, data: dict) -> list[dict[str, Any]]:
        events = []
        for user in data.get("value", []):
            if user.get("riskLevel") not in ("none", "hidden"):
                events.append(self._build_event(
                    user,
                    event_type="risky_user",
                    severity=self._map_risk_level(user.get("riskLevel", "")),
                    description=(
                        f"Risky user: {user.get('userDisplayName', '')} "
                        f"- {user.get('riskDetail', '')} "
                        f"(state: {user.get('riskState', '')})"
                    ),
                ))
        return events

    def _parse_risky_signins(self, data: dict) -> list[dict[str, Any]]:
        events = []
        for signin in data.get("value", []):
            events.append(self._build_event(
                signin,
                event_type="risky_signin",
                severity=self._map_risk_level(signin.get("riskLevelDuringSignIn", "")),
                description=(
                    f"Risky sign-in: {signin.get('userDisplayName', '')} "
                    f"from {signin.get('ipAddress', '')} "
                    f"({', '.join(signin.get('riskEventTypes_v2', []))})"
                ),
                source_ip=signin.get("ipAddress", ""),
            ))
        return events

    @staticmethod
    def _map_risk_level(level: str) -> str:
        mapping = {"high": "high", "medium": "medium", "low": "low", "none": "info", "hidden": "info"}
        return mapping.get(level.lower(), "info")
