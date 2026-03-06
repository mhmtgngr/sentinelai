"""Real-time WebSocket feeds for Sentinel-AI."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from src.core.event_bus import Event, EventBus, EventType

router = APIRouter()
logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._subscriptions: dict[int, set[str]] = {}  # ws_id -> set of event types

    async def connect(self, websocket: WebSocket, event_types: list[str] | None = None) -> None:
        await websocket.accept()
        self._connections.append(websocket)
        ws_id = id(websocket)
        if event_types:
            self._subscriptions[ws_id] = set(event_types)
        else:
            self._subscriptions[ws_id] = set()  # Empty = all events
        logger.info("WebSocket connected: %s", ws_id)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections = [ws for ws in self._connections if ws is not websocket]
        self._subscriptions.pop(id(websocket), None)

    async def broadcast(self, event: Event) -> None:
        message = {
            "event_type": event.event_type.value,
            "event_id": event.event_id,
            "source": event.source,
            "timestamp": event.timestamp.isoformat(),
            "data": _serialize(event.data),
        }
        payload = json.dumps(message, default=str)

        disconnected = []
        for ws in self._connections:
            ws_id = id(ws)
            subs = self._subscriptions.get(ws_id, set())
            # Empty subs = send all, otherwise filter
            if subs and event.event_type.value not in subs:
                continue
            try:
                await ws.send_text(payload)
            except Exception:
                disconnected.append(ws)

        for ws in disconnected:
            self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time event streaming."""
    # Parse query params for event type filtering
    event_types = websocket.query_params.get("types", "").split(",")
    event_types = [t.strip() for t in event_types if t.strip()]

    await manager.connect(websocket, event_types or None)

    try:
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "subscribe":
                    ws_id = id(websocket)
                    new_types = msg.get("event_types", [])
                    manager._subscriptions[ws_id] = set(new_types)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


def setup_event_broadcasting(event_bus: EventBus) -> None:
    """Subscribe to all event types and broadcast to WebSocket clients."""
    for event_type in EventType:
        event_bus.subscribe(event_type, manager.broadcast)


def _serialize(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    return obj
