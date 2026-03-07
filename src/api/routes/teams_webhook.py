"""Microsoft Teams webhook callback endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

from src.core.orchestrator import get_orchestrator

router = APIRouter(prefix="/teams", tags=["Teams"])


@router.post("/callback")
async def teams_callback(request: Request) -> dict:
    """Receive adaptive card action callbacks from Microsoft Teams.

    This endpoint is called when an analyst clicks a button on the
    decision adaptive card in Teams.
    """
    body = await request.json()

    # Extract analyst identity from Teams payload if available
    analyst = "teams_user"
    if "from" in body:
        analyst = body["from"].get("name", analyst)

    response_data = {
        "alert_id": body.get("alert_id", ""),
        "action": body.get("action", ""),
        "reason": body.get("reason", ""),
        "analyst": analyst,
    }

    orch = get_orchestrator()
    decision = await orch.teams.process_response(response_data)

    if decision:
        return {
            "status": "decision_recorded",
            "decision_id": decision.id,
            "action": decision.action.value,
        }
    return {"status": "ignored", "message": "No pending decision for this alert"}


@router.post("/notify")
async def send_teams_notification(payload: dict) -> dict:
    """Manually send a notification to the Teams channel."""
    orch = get_orchestrator()
    await orch.teams.send_notification(
        title=payload.get("title", "Notification"),
        message=payload.get("message", ""),
        severity=payload.get("severity", "medium"),
    )
    return {"status": "sent"}
