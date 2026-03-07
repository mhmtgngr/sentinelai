"""FastAPI application — SENTINEL-AI autonomous blue team platform."""

from __future__ import annotations

import logging

from fastapi import FastAPI

from src.core.config import settings
from src.core.orchestrator import get_orchestrator
from src.api.routes import alerts, teams_webhook, education, health

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="SENTINEL-AI",
    description="Autonomous AI Blue Team Security Operations Platform",
    version="0.1.0",
)

# Register routes
app.include_router(health.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(teams_webhook.router, prefix="/api/v1")
app.include_router(education.router, prefix="/api/v1")


@app.on_event("startup")
async def startup() -> None:
    # Initialize the orchestrator (wires up all event subscribers)
    get_orchestrator()
    logging.getLogger(__name__).info("SENTINEL-AI started — autonomous mode: %s", settings.autonomous_mode)
