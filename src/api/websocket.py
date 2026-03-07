"""WebSocket manager for real-time event streaming.

Manages WebSocket connections, topic subscriptions, and event broadcasting.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from src.core.event_bus import EventBus

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections and event broadcasting.

    Clients can subscribe to specific event topics or receive all events.
    """

    def __init__(self, event_bus: EventBus) -> None:
        self._event_bus = event_bus
        self._connections: dict[WebSocket, set[str]] = {}
        self._all_topics = [
            "alert.new", "alert.triaged", "threat.confirmed",
            "incident.created", "action.executed", "action.pending_approval",
            "adapter.health",
        ]

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a WebSocket connection."""
        await websocket.accept()
        self._connections[websocket] = set(self._all_topics)
        logger.info("WebSocket client connected (total: %d)", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        self._connections.pop(websocket, None)
        logger.info("WebSocket client disconnected (total: %d)", len(self._connections))

    async def handle_subscription(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """Update topic subscriptions for a client."""
        topics = message.get("subscribe", [])
        if topics and websocket in self._connections:
            self._connections[websocket] = set(topics)
            logger.debug("Client updated subscriptions: %s", topics)

    async def broadcast(self, topic: str, data: dict[str, Any]) -> None:
        """Send an event to all subscribed WebSocket clients."""
        message = json.dumps({"type": topic, "data": data})
        disconnected: list[WebSocket] = []

        for ws, subscriptions in self._connections.items():
            if topic in subscriptions:
                try:
                    await ws.send_text(message)
                except Exception:
                    disconnected.append(ws)

        for ws in disconnected:
            self.disconnect(ws)

    def register_with_event_bus(self) -> None:
        """Subscribe to all event bus topics and forward to WebSocket clients."""
        for topic in self._all_topics:
            self._event_bus.subscribe(topic, lambda data, t=topic: self.broadcast(t, data))

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def handle_client(self, websocket: WebSocket) -> None:
        """Main handler for a WebSocket client connection."""
        await self.connect(websocket)
        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    message = json.loads(raw)
                    await self.handle_subscription(websocket, message)
                except json.JSONDecodeError:
                    pass
        except WebSocketDisconnect:
            self.disconnect(websocket)
