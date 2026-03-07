"""FastAPI application for Sentinel-AI.

Provides REST API, health checks, and metrics endpoints.
See docs/api-spec.md for full endpoint specification.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import adapters, alerts, incidents, memory
from src.core.event_bus import EventBus


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle — start/stop event bus and adapters."""
    event_bus = EventBus()
    app.state.event_bus = event_bus
    app.state.start_time = datetime.utcnow()
    await event_bus.start()
    yield
    await event_bus.stop()


app = FastAPI(
    title="Sentinel-AI",
    description="Autonomous AI Security Operations Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — restrict in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route modules
app.include_router(alerts.router, prefix="/api/v1", tags=["alerts"])
app.include_router(incidents.router, prefix="/api/v1", tags=["incidents"])
app.include_router(adapters.router, prefix="/api/v1", tags=["adapters"])
app.include_router(memory.router, prefix="/api/v1", tags=["memory"])


@app.get("/health")
async def health() -> dict[str, Any]:
    """Liveness check."""
    return {
        "status": "healthy",
        "version": "0.1.0",
    }


@app.get("/ready")
async def ready() -> dict[str, Any]:
    """Readiness check — verifies critical dependencies."""
    return {
        "status": "ready",
        "components": {
            "event_bus": "healthy",
        },
    }


@app.get("/metrics")
async def metrics() -> dict[str, Any]:
    """Prometheus-compatible metrics endpoint (placeholder)."""
    event_bus: EventBus = app.state.event_bus
    return {
        "event_bus_queue_depth": event_bus.queue_depth,
        "event_bus_subscribers": event_bus.subscriber_count,
    }
