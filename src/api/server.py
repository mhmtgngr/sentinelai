"""FastAPI REST API server for Sentinel-AI."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from src.api.routes.alerts import router as alerts_router
from src.api.routes.incidents import router as incidents_router
from src.api.routes.adapters import router as adapters_router
from src.api.routes.memory import router as memory_router
from src.api.routes.detection import router as detection_router
from src.api.routes.system import router as system_router
from src.api.routes.approvals import router as approvals_router
from src.api.websocket import router as ws_router
from src.core.brain import SentinelBrain
from src.core.config import SentinelConfig
from src.core.event_bus import EventBus


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle for the API server."""
    config = SentinelConfig.from_yaml()
    event_bus = EventBus()
    brain = SentinelBrain(config=config, event_bus=event_bus)

    app.state.config = config
    app.state.event_bus = event_bus
    app.state.brain = brain

    await brain.start()
    yield
    await brain.stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sentinel-AI",
        description="Autonomous AI Security Operations Platform API",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.include_router(system_router, prefix="/api/v1", tags=["system"])
    app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["alerts"])
    app.include_router(incidents_router, prefix="/api/v1/incidents", tags=["incidents"])
    app.include_router(adapters_router, prefix="/api/v1/adapters", tags=["adapters"])
    app.include_router(memory_router, prefix="/api/v1/memory", tags=["memory"])
    app.include_router(detection_router, prefix="/api/v1/detection", tags=["detection"])
    app.include_router(approvals_router, prefix="/api/v1/approvals", tags=["approvals"])
    app.include_router(ws_router, tags=["websocket"])

    return app
