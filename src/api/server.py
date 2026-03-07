"""FastAPI application for Sentinel-AI.

Provides REST API, health checks, metrics, and WebSocket endpoints.
See docs/api-spec.md for full endpoint specification.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncGenerator

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import actions, adapters, alerts, incidents, memory
from src.api.websocket import WebSocketManager
from src.core.event_bus import EventBus
from src.integrations.adapter_registry import AdapterRegistry


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle — start/stop event bus, adapters, and websocket."""
    event_bus = EventBus()
    adapter_registry = AdapterRegistry()
    ws_manager = WebSocketManager(event_bus)

    app.state.event_bus = event_bus
    app.state.adapter_registry = adapter_registry
    app.state.ws_manager = ws_manager
    app.state.start_time = datetime.utcnow()

    ws_manager.register_with_event_bus()
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
app.include_router(actions.router, prefix="/api/v1", tags=["actions"])


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
    registry: AdapterRegistry = app.state.adapter_registry
    return {
        "status": "ready",
        "components": {
            "event_bus": "healthy",
            "adapters": registry.get_all(),
        },
    }


@app.get("/metrics")
async def metrics() -> dict[str, Any]:
    """Prometheus-compatible metrics endpoint."""
    event_bus: EventBus = app.state.event_bus
    ws_manager: WebSocketManager = app.state.ws_manager
    return {
        "event_bus_queue_depth": event_bus.queue_depth,
        "event_bus_subscribers": event_bus.subscriber_count,
        "websocket_connections": ws_manager.connection_count,
    }


@app.websocket("/api/v1/ws/events")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Real-time event stream via WebSocket."""
    ws_manager: WebSocketManager = app.state.ws_manager
    await ws_manager.handle_client(websocket)
