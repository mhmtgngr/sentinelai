"""Adapter management API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/")
async def list_adapters(request: Request) -> dict[str, Any]:
    """List all registered adapters and their status."""
    brain = request.app.state.brain
    adapters = {}
    for name, adapter in brain._adapters.items():
        adapters[name] = {
            "vendor": adapter.vendor,
            "product_type": adapter.product_type,
            "connected": adapter.is_connected,
            "endpoint": adapter.endpoint,
        }
    return {"adapters": adapters}


@router.get("/{adapter_name}/health")
async def adapter_health(adapter_name: str, request: Request) -> dict[str, Any]:
    """Check health of a specific adapter."""
    brain = request.app.state.brain
    adapter = brain._adapters.get(adapter_name)
    if not adapter:
        return {"error": f"Adapter '{adapter_name}' not found"}
    health = await adapter.health_check()
    return {"adapter": adapter_name, "health": health.value}
