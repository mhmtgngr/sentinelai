"""Alert management endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()

_alerts: dict[str, dict[str, Any]] = {}


@router.get("/alerts")
async def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List alerts with filtering and pagination."""
    alerts = list(_alerts.values())
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity.upper()]
    total = len(alerts)
    alerts = alerts[offset : offset + limit]
    return {"alerts": alerts, "total": total, "limit": limit, "offset": offset}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str) -> dict:
    """Get detailed alert with all events."""
    alert = _alerts.get(alert_id)
    if alert:
        return alert
    return {"alert_id": alert_id, "detail": "not_found"}


@router.post("/alerts/{alert_id}/verdict")
async def submit_verdict(alert_id: str, verdict: str = "UNDETERMINED", notes: str = "") -> dict:
    """Submit analyst verdict for an alert."""
    if alert_id in _alerts:
        _alerts[alert_id]["triage_verdict"] = verdict
        _alerts[alert_id]["analyst_notes"] = notes
    return {"alert_id": alert_id, "status": "verdict_recorded", "verdict": verdict}
