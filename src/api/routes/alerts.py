"""Alert management API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.core.event_bus import Event, EventType

router = APIRouter()


class AlertSubmission(BaseModel):
    source: str = ""
    severity: str = "info"
    description: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    rule_id: str = ""
    rule_name: str = ""
    raw_data: dict[str, Any] = {}


class FeedbackSubmission(BaseModel):
    alert_id: str
    verdict: str  # true_positive, false_positive, benign, needs_tuning
    analyst_notes: str = ""
    rule_id: str = ""


@router.post("/")
async def submit_alert(alert: AlertSubmission, request: Request) -> dict[str, Any]:
    """Submit a new security alert for triage."""
    event_bus = request.app.state.event_bus
    event = Event(
        event_type=EventType.ALERT_RECEIVED,
        data=alert.model_dump(),
        source=alert.source or "api",
    )
    await event_bus.publish(event)
    return {"status": "accepted", "event_id": event.event_id}


@router.get("/history")
async def get_alert_history(request: Request, limit: int = 100, event_type: str | None = None) -> dict[str, Any]:
    """Get recent alert history."""
    event_bus = request.app.state.event_bus
    et = EventType(event_type) if event_type else EventType.ALERT_RECEIVED
    history = event_bus.get_history(event_type=et, limit=limit)
    return {
        "count": len(history),
        "alerts": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "source": e.source,
                "timestamp": e.timestamp.isoformat(),
                "data": e.data,
            }
            for e in history
        ],
    }


@router.post("/feedback")
async def submit_feedback(feedback: FeedbackSubmission, request: Request) -> dict[str, Any]:
    """Submit analyst feedback on an alert (for learning engine)."""
    event_bus = request.app.state.event_bus
    await event_bus.publish(Event(
        event_type=EventType.FEEDBACK_RECEIVED,
        data=feedback.model_dump(),
        source="api",
    ))
    return {"status": "recorded", "alert_id": feedback.alert_id}
