"""Incident management API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.core.event_bus import EventType

router = APIRouter()


class IncidentClose(BaseModel):
    resolution: str


@router.get("/")
async def list_incidents(request: Request, status: str | None = None) -> dict[str, Any]:
    """List all incidents."""
    event_bus = request.app.state.event_bus
    history = event_bus.get_history(event_type=EventType.INCIDENT_CREATED, limit=500)
    incidents = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "data": e.data,
        }
        for e in history
    ]
    if status:
        incidents = [i for i in incidents if i["data"].get("status") == status]
    return {"count": len(incidents), "incidents": incidents}


@router.get("/{incident_id}")
async def get_incident(incident_id: str, request: Request) -> dict[str, Any]:
    """Get incident details."""
    brain = request.app.state.brain
    responder = brain._agents.get("incident_responder")
    if responder:
        incident = responder.get_incident(incident_id)
        if incident:
            return {
                "incident_id": incident.incident_id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "attack_type": incident.attack_type,
                "actions_taken": incident.actions_taken,
                "timeline": incident.timeline,
                "created_at": incident.created_at.isoformat(),
            }
    return {"error": "Incident not found"}


@router.post("/{incident_id}/close")
async def close_incident(incident_id: str, body: IncidentClose, request: Request) -> dict[str, Any]:
    """Close an incident with a resolution."""
    brain = request.app.state.brain
    responder = brain._agents.get("incident_responder")
    if responder:
        success = responder.close_incident(incident_id, body.resolution)
        return {"success": success, "incident_id": incident_id}
    return {"error": "Incident responder not available"}
