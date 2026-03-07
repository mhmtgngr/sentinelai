"""Tests for WebSocket manager."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.api.websocket import WebSocketManager
from src.core.event_bus import EventBus


@pytest.mark.asyncio
async def test_websocket_manager_creation():
    event_bus = EventBus()
    manager = WebSocketManager(event_bus)
    assert manager is not None
    assert manager.connection_count == 0


@pytest.mark.asyncio
async def test_register_with_event_bus():
    event_bus = EventBus()
    manager = WebSocketManager(event_bus)
    manager.register_with_event_bus()


@pytest.mark.asyncio
async def test_connect_and_disconnect():
    event_bus = EventBus()
    manager = WebSocketManager(event_bus)

    ws = AsyncMock()
    ws.accept = AsyncMock()

    await manager.connect(ws)
    assert manager.connection_count == 1

    manager.disconnect(ws)  # sync method
    assert manager.connection_count == 0


@pytest.mark.asyncio
async def test_broadcast():
    event_bus = EventBus()
    manager = WebSocketManager(event_bus)

    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()

    await manager.connect(ws)
    await manager.broadcast("alert.new", {"alert_id": "test"})

    ws.send_text.assert_called_once()


@pytest.mark.asyncio
async def test_broadcast_no_connections():
    event_bus = EventBus()
    manager = WebSocketManager(event_bus)
    await manager.broadcast("alert.new", {"data": "test"})


@pytest.mark.asyncio
async def test_disconnect_nonexistent():
    event_bus = EventBus()
    manager = WebSocketManager(event_bus)
    ws = AsyncMock()
    manager.disconnect(ws)  # sync, should not raise
    assert manager.connection_count == 0


@pytest.mark.asyncio
async def test_subscription_filtering():
    event_bus = EventBus()
    manager = WebSocketManager(event_bus)

    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()

    await manager.connect(ws)
    # Subscribe only to alert.new
    await manager.handle_subscription(ws, {"subscribe": ["alert.new"]})

    # Broadcast to a topic the client is NOT subscribed to
    await manager.broadcast("incident.created", {"id": "test"})
    ws.send_text.assert_not_called()

    # Broadcast to subscribed topic
    await manager.broadcast("alert.new", {"id": "test"})
    ws.send_text.assert_called_once()
