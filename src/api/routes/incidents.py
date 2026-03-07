"""Incident management endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()

_incidents: dict[str, dict[str, Any]] = {}


@router.get("/incidents")
async def list_incidents(
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List incidents with filtering."""
    incidents = list(_incidents.values())
    if status:
        incidents = [i for i in incidents if i.get("status") == status.upper()]
    total = len(incidents)
    incidents = incidents[offset : offset + limit]
    return {"incidents": incidents, "total": total, "limit": limit, "offset": offset}


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict:
    """Get detailed incident with timeline."""
    incident = _incidents.get(incident_id)
    if incident:
        return incident
    return {"incident_id": incident_id, "detail": "not_found"}


@router.post("/investigations")
async def create_investigation(
    type: str = "hunt",
    target: str = "",
    context: str = "",
    priority: int = 2,
) -> dict:
    """Trigger a manual investigation (used by OpenClaw skills)."""
    return {"status": "queued", "type": type, "target": target}


@router.post("/incidents/{incident_id}/actions/{action_id}/approve")
async def approve_action(incident_id: str, action_id: str) -> dict:
    """Approve a pending action."""
    return {"incident_id": incident_id, "action_id": action_id, "status": "approved"}


@router.post("/incidents/{incident_id}/actions/{action_id}/deny")
async def deny_action(incident_id: str, action_id: str) -> dict:
    """Deny a pending action."""
    return {"incident_id": incident_id, "action_id": action_id, "status": "denied"}
