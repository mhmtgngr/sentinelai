"""Action management endpoints."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()

# In-memory action store (replaced by database in production)
_actions: dict[str, dict] = {}


@router.get("/actions/{action_id}")
async def get_action(action_id: str) -> dict:
    """Get action details including rollback status."""
    action = _actions.get(action_id)
    if action:
        return action
    return {"action_id": action_id, "status": "not_found"}


@router.post("/actions/{action_id}/rollback")
async def rollback_action(action_id: str) -> dict:
    """Rollback a previously executed action."""
    action = _actions.get(action_id)
    if action and action.get("rollback_capable"):
        action["status"] = "ROLLED_BACK"
        return {"action_id": action_id, "status": "ROLLED_BACK"}
    return {"action_id": action_id, "status": "rollback_not_available"}
