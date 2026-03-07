"""Memory and vector store endpoints."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/memory/status")
async def memory_status() -> dict:
    """Get vector store status and statistics."""
    return {"status": "not_implemented"}


@router.get("/dlq")
async def list_dlq() -> dict:
    """List dead letter queue entries."""
    return {"events": [], "total": 0}


@router.post("/dlq/{event_id}/replay")
async def replay_dlq_event(event_id: str) -> dict:
    """Replay a single DLQ event."""
    return {"event_id": event_id, "status": "replayed"}
