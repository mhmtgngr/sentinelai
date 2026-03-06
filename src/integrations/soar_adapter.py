"""SOAR adapters (Shuffle, Tracecat)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.integrations.base_adapter import ActionResult, BaseSecurityAdapter, HealthStatus


class ShuffleAdapter(BaseSecurityAdapter):
    product_type = "soar"
    vendor = "shuffle"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_key = config.get("api_key") or os.getenv("SHUFFLE_API_KEY", "")
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.endpoint,
            headers={"Authorization": f"Bearer {self._api_key}"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        """Get recent workflow execution results."""
        if not self._client:
            return []
        try:
            resp = await self._client.get("/api/v1/workflows/executions")
            resp.raise_for_status()
            return self._parse_executions(resp.json())
        except Exception:
            self.logger.exception("Error fetching Shuffle executions")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/api/v1/health")
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def execute_workflow(self, workflow_id: str, params: dict) -> ActionResult:
        """Trigger a Shuffle SOAR workflow."""
        if not self._client:
            return ActionResult(success=False, action="execute_workflow", message="Not connected")
        try:
            resp = await self._client.post(
                f"/api/v1/workflows/{workflow_id}/execute",
                json={"execution_argument": params},
            )
            return ActionResult(
                success=resp.status_code in (200, 201),
                action="execute_workflow",
                message=f"Workflow {workflow_id} triggered",
                data=resp.json() if resp.status_code in (200, 201) else {},
            )
        except Exception as e:
            return ActionResult(success=False, action="execute_workflow", message=str(e))

    def _parse_executions(self, data: list | dict) -> list[dict[str, Any]]:
        items = data if isinstance(data, list) else data.get("executions", [])
        events = []
        for ex in items:
            if ex.get("status") == "ABORTED" or ex.get("status") == "FAILURE":
                events.append(self._build_event(
                    ex,
                    event_type="workflow_failure",
                    severity="medium",
                    description=f"Workflow {ex.get('workflow_id', '')} {ex.get('status', '')}",
                ))
        return events


class TracecatAdapter(BaseSecurityAdapter):
    product_type = "soar"
    vendor = "tracecat"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._api_key = config.get("api_key") or os.getenv("TRACECAT_API_KEY", "")
        self._client: httpx.AsyncClient | None = None

    async def _authenticate(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.endpoint or "http://localhost:8000",
            headers={"Authorization": f"Bearer {self._api_key}"},
            timeout=30.0,
        )

    async def get_events(self, since: datetime | None = None) -> list[dict[str, Any]]:
        if not self._client:
            return []
        try:
            resp = await self._client.get("/api/cases")
            resp.raise_for_status()
            return self._parse_cases(resp.json())
        except Exception:
            self.logger.exception("Error fetching Tracecat cases")
            return []

    async def health_check(self) -> HealthStatus:
        if not self._client:
            return HealthStatus.UNHEALTHY
        try:
            resp = await self._client.get("/api/health")
            return HealthStatus.HEALTHY if resp.status_code == 200 else HealthStatus.DEGRADED
        except Exception:
            return HealthStatus.UNHEALTHY

    async def create_case(self, title: str, description: str, severity: str) -> ActionResult:
        """Create a new case in Tracecat."""
        if not self._client:
            return ActionResult(success=False, action="create_case", message="Not connected")
        try:
            resp = await self._client.post(
                "/api/cases",
                json={"title": title, "description": description, "severity": severity},
            )
            return ActionResult(
                success=resp.status_code in (200, 201),
                action="create_case",
                message=f"Case created: {title}",
                data=resp.json() if resp.status_code in (200, 201) else {},
            )
        except Exception as e:
            return ActionResult(success=False, action="create_case", message=str(e))

    def _parse_cases(self, data: list | dict) -> list[dict[str, Any]]:
        items = data if isinstance(data, list) else data.get("cases", [])
        events = []
        for case in items:
            if case.get("status") in ("open", "in_progress"):
                events.append(self._build_event(
                    case,
                    event_type="case",
                    severity=case.get("severity", "info"),
                    description=case.get("title", ""),
                ))
        return events
