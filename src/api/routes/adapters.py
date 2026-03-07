"""Adapter management endpoints."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/adapters/health")
async def adapter_health() -> dict:
    """Get health status of all registered adapters."""
    return {"adapters": {}}


@router.get("/adapters/{adapter_id}/health")
async def adapter_detail_health(adapter_id: str) -> dict:
    """Get detailed health for a specific adapter."""
    return {"adapter_id": adapter_id, "detail": "not_implemented"}
