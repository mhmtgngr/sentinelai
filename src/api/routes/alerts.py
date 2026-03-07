"""Alert ingestion and query endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from src.core.models import Alert, AlertStatus, Severity
from src.core.orchestrator import get_orchestrator

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.post("/", status_code=201)
async def ingest_alert(alert: Alert) -> dict:
    """Ingest a new security alert into the autonomous pipeline."""
    orch = get_orchestrator()
    processed = await orch.ingest_alert(alert)
    return {
        "status": "accepted",
        "alert_id": processed.id,
        "message": "Alert ingested and triage pipeline started",
    }


@router.post("/batch", status_code=201)
async def ingest_alerts(alerts: list[Alert]) -> dict:
    """Ingest multiple alerts at once."""
    orch = get_orchestrator()
    ids = []
    for alert in alerts:
        processed = await orch.ingest_alert(alert)
        ids.append(processed.id)
    return {"status": "accepted", "alert_ids": ids, "count": len(ids)}


@router.get("/")
async def list_alerts(
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    limit: int = 50,
) -> list[dict]:
    """List alerts with optional filters."""
    orch = get_orchestrator()
    alerts = list(orch.alerts.values())
    if status:
        alerts = [a for a in alerts if a.status == status]
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    alerts.sort(key=lambda a: a.timestamp, reverse=True)
    return [a.model_dump(mode="json") for a in alerts[:limit]]


@router.get("/{alert_id}")
async def get_alert(alert_id: str) -> dict:
    """Get a single alert by ID."""
    orch = get_orchestrator()
    alert = orch.alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.model_dump(mode="json")
