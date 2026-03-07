"""Incident management endpoints."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/incidents")
async def list_incidents(
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List incidents with filtering."""
    return {"incidents": [], "total": 0, "limit": limit, "offset": offset}


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict:
    """Get detailed incident with timeline."""
    return {"incident_id": incident_id, "detail": "not_implemented"}


@router.post("/investigations")
async def create_investigation(
    type: str = "hunt",
    target: str = "",
    context: str = "",
    priority: int = 2,
) -> dict:
    """Trigger a manual investigation (used by OpenClaw skills)."""
    return {"status": "queued", "type": type, "target": target}
