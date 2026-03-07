"""Identity Adapter — Microsoft Entra ID (Azure AD) integration.

User management via Microsoft Graph API.
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


class IdentityAdapter(BaseSecurityAdapter):
    product_type = "identity"
    vendor = "entraid"

    def __init__(self, endpoint: str, tenant_id: str = "", client_id: str = "", client_secret: str = "", **kwargs: Any) -> None:
        super().__init__(endpoint, **kwargs)
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._client = httpx.AsyncClient(base_url="https://graph.microsoft.com/v1.0", timeout=30.0)
        self._token: str | None = None

    async def _authenticate(self) -> str:
        token_client = httpx.AsyncClient()
        response = await token_client.post(
            f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": self._client_id, "client_secret": self._client_secret, "scope": "https://graph.microsoft.com/.default"},
        )
        response.raise_for_status()
        self._token = response.json()["access_token"]
        self._client.headers["Authorization"] = f"Bearer {self._token}"
        await token_client.aclose()
        return self._token

    async def get_events(self, since: datetime) -> list[SecurityEvent]:
        if not self._token:
            await self._authenticate()

        response = await self._client.get("/security/alerts_v2", params={"$filter": f"createdDateTime ge {since.isoformat()}Z", "$top": 100})
        response.raise_for_status()

        events = []
        for alert in response.json().get("value", []):
            events.append(SecurityEvent(
                source_adapter=f"{self.product_type}/{self.vendor}",
                event_type=alert.get("title", "unknown"),
                severity=self._map_severity(alert.get("severity", "medium")),
                raw_payload=alert,
                normalized={"user": alert.get("userStates", [{}])[0].get("userPrincipalName", "") if alert.get("userStates") else "", "category": alert.get("category", "")},
                affected_assets=[u.get("userPrincipalName", "") for u in alert.get("userStates", [])],
            ))
        return events

    async def execute_action(self, action_type: ActionType, target: str, params: dict[str, Any] | None = None) -> ActionResult:
        if not self._token:
            await self._authenticate()

        if action_type == ActionType.DISABLE_ACCOUNT:
            try:
                response = await self._client.patch(f"/users/{target}", json={"accountEnabled": False})
                response.raise_for_status()
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.SUCCESS, adapter_used=f"{self.product_type}/{self.vendor}", rollback_capable=True, rollback_procedure=f"Re-enable account {target}", executed_at=datetime.utcnow())
            except httpx.HTTPError as e:
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, evidence={"error": str(e)})

        if action_type == ActionType.FORCE_PASSWORD_RESET:
            try:
                response = await self._client.patch(f"/users/{target}", json={"passwordProfile": {"forceChangePasswordNextSignIn": True}})
                response.raise_for_status()
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.SUCCESS, adapter_used=f"{self.product_type}/{self.vendor}", executed_at=datetime.utcnow())
            except httpx.HTTPError as e:
                return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, evidence={"error": str(e)})

        return ActionResult(action_type=action_type, target=target, status=ActionStatus.FAILED, evidence={"error": "unsupported"})

    async def health_check(self) -> HealthStatus:
        try:
            if not self._token:
                await self._authenticate()
            response = await self._client.get("/organization")
            response.raise_for_status()
            return HealthStatus(state=HealthState.HEALTHY, message="Microsoft Graph reachable")
        except Exception as e:
            return HealthStatus(state=HealthState.UNAVAILABLE, message=str(e))

    @staticmethod
    def _map_severity(ms_severity: str) -> Severity:
        return {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "informational": Severity.INFO}.get(ms_severity.lower(), Severity.MEDIUM)
