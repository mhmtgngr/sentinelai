"""Education endpoints — manually trigger or query education records."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from src.core.models import Alert, AlertCategory
from src.core.orchestrator import get_orchestrator
from src.education.content import get_category_topics, get_education_html

router = APIRouter(prefix="/education", tags=["Education"])


@router.post("/send")
async def send_education(payload: dict) -> dict:
    """Manually send education to a user for a specific alert.

    Body: {"alert_id": "...", "topics": ["topic1", "topic2"]}
    If topics is omitted, topics are auto-selected based on alert category.
    """
    orch = get_orchestrator()
    alert_id = payload.get("alert_id")
    if not alert_id or alert_id not in orch.alerts:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = orch.alerts[alert_id]
    topics = payload.get("topics")
    record = await orch.education_manager.send_education(alert, topics)

    if record:
        return {"status": "sent", "education_id": record.id, "topics": record.topics}
    return {"status": "skipped", "message": "No affected user on this alert"}


@router.get("/topics/{category}")
async def get_topics(category: str) -> dict:
    """Get available education topics for an alert category."""
    try:
        cat = AlertCategory(category)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown category: {category}")
    topics = get_category_topics(cat)
    return {"category": category, "topics": topics}


@router.get("/preview/{topic}")
async def preview_education(topic: str) -> dict:
    """Preview education content for a specific topic."""
    html = get_education_html([topic])
    return {"topic": topic, "html": html}
