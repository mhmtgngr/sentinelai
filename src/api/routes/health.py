"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from src.core.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health() -> dict:
    return {
        "status": "healthy",
        "service": "sentinel-ai",
        "autonomous_mode": settings.autonomous_mode,
        "teams_configured": bool(settings.teams_webhook_url),
        "smtp_configured": bool(settings.smtp_host and settings.smtp_user),
    }
