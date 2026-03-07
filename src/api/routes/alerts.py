"""Alert management endpoints."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/alerts")
async def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List alerts with filtering and pagination."""
    return {"alerts": [], "total": 0, "limit": limit, "offset": offset}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str) -> dict:
    """Get detailed alert with all events."""
    return {"alert_id": alert_id, "detail": "not_implemented"}


@router.post("/alerts/{alert_id}/verdict")
async def submit_verdict(alert_id: str) -> dict:
    """Submit analyst verdict for an alert."""
    return {"alert_id": alert_id, "status": "verdict_recorded"}
