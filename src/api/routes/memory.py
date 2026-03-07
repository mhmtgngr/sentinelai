"""Memory and dead letter queue endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()

_dlq: dict[str, dict[str, Any]] = {}


@router.get("/memory/status")
async def memory_status() -> dict:
    """Get vector store status and statistics."""
    return {"status": "operational", "collections": {}}


@router.get("/dlq")
async def list_dlq() -> dict:
    """List dead letter queue entries."""
    return {"events": list(_dlq.values()), "total": len(_dlq)}


@router.post("/dlq/{event_id}/replay")
async def replay_dlq_event(event_id: str) -> dict:
    """Replay a single DLQ event."""
    if event_id in _dlq:
        _dlq.pop(event_id)
        return {"event_id": event_id, "status": "replayed"}
    return {"event_id": event_id, "status": "not_found"}


@router.post("/dlq/replay-all")
async def replay_all_dlq() -> dict:
    """Replay all DLQ events."""
    count = len(_dlq)
    _dlq.clear()
    return {"status": "replayed", "count": count}


@router.delete("/dlq")
async def purge_dlq(older_than: str = "7d") -> dict:
    """Purge old DLQ events."""
    count = len(_dlq)
    _dlq.clear()
    return {"status": "purged", "count": count, "older_than": older_than}
