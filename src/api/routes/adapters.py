"""Adapter management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/adapters/health")
async def adapter_health(request: Request) -> dict:
    """Get health status of all registered adapters."""
    registry = getattr(request.app.state, "adapter_registry", None)
    if registry:
        return {"adapters": registry.get_all()}
    return {"adapters": {}}


@router.get("/adapters/{adapter_id}/health")
async def adapter_detail_health(adapter_id: str, request: Request) -> dict:
    """Get detailed health for a specific adapter."""
    registry = getattr(request.app.state, "adapter_registry", None)
    if registry:
        adapter = registry.get(adapter_id)
        if adapter:
            return {
                "adapter_id": adapter_id,
                "product_type": adapter.product_type,
                "vendor": adapter.vendor,
                "health_state": adapter.health_state.value,
            }
    return {"adapter_id": adapter_id, "detail": "not_found"}
