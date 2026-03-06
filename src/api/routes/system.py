"""System status and health API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "sentinel-ai"}


@router.get("/status")
async def system_status(request: Request) -> dict[str, Any]:
    """Get full system status including brain, agents, and adapters."""
    brain = request.app.state.brain
    return brain.get_status()
