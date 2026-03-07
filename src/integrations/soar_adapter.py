"""SOAR Adapter — Shuffle SOAR integration.

Triggers automated workflows and playbooks via Shuffle API.
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


class SOARAdapter(BaseSecurityAdapter):
    product_type = "soar"
    vendor = "shuffle"

    def __init__(self, endpoint: str, api_key: str = "", **kwargs: Any) -> None:
        super().__init__(endpoint, **kwargs)
        self._client = httpx.AsyncClient(
            base_url=endpoint,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime) -> list[SecurityEvent]:
        """Shuffle is primarily an orchestrator — minimal event ingestion."""
        try:
            response = await self._client.get("/api/v1/workflows/queue", params={"limit": 50})
            response.raise_for_status()
            events = []
            for item in response.json().get("data", []):
                events.append(SecurityEvent(
                    source_adapter=f"{self.product_type}/{self.vendor}",
                    event_type="workflow_result",
                    severity=Severity.INFO,
                    raw_payload=item,
                    normalized={"workflow_id": item.get("workflow_id"), "status": item.get("status")},
                ))
            return events
        except Exception:
            return []

    async def execute_action(self, action_type: ActionType, target: str, params: dict[str, Any] | None = None) -> ActionResult:
        """Trigger a Shuffle workflow."""
        workflow_id = (params or {}).get("workflow_id", target)

        try:
            response = await self._client.post(
                f"/api/v1/workflows/{workflow_id}/execute",
                json={"execution_argument": target, "start": ""},
            )
            response.raise_for_status()
            execution_id = response.json().get("execution_id", "")

            return ActionResult(
                action_type=action_type,
                target=target,
                status=ActionStatus.SUCCESS,
                adapter_used=f"{self.product_type}/{self.vendor}",
                evidence={"execution_id": execution_id, "workflow_id": workflow_id},
                executed_at=datetime.utcnow(),
            )
        except httpx.HTTPError as e:
            return ActionResult(
                action_type=action_type,
                target=target,
                status=ActionStatus.FAILED,
                adapter_used=f"{self.product_type}/{self.vendor}",
                evidence={"error": str(e)},
            )

    async def health_check(self) -> HealthStatus:
        try:
            response = await self._client.get("/api/v1/health")
            response.raise_for_status()
            return HealthStatus(state=HealthState.HEALTHY, message="Shuffle API reachable")
        except Exception as e:
            return HealthStatus(state=HealthState.UNAVAILABLE, message=str(e))
