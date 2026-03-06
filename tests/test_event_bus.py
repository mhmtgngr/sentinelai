"""Tests for the event bus system."""

import asyncio
import pytest
from src.core.event_bus import EventBus, Event, EventType


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.mark.asyncio
async def test_publish_subscribe(event_bus):
    received = []

    async def handler(event: Event):
        received.append(event)

    event_bus.subscribe(EventType.ALERT_RECEIVED, handler)
    event = Event(event_type=EventType.ALERT_RECEIVED, data={"test": True}, source="test")
    await event_bus.publish(event)

    assert len(received) == 1
    assert received[0].data == {"test": True}


@pytest.mark.asyncio
async def test_multiple_subscribers(event_bus):
    count = {"a": 0, "b": 0}

    async def handler_a(event: Event):
        count["a"] += 1

    async def handler_b(event: Event):
        count["b"] += 1

    event_bus.subscribe(EventType.ALERT_RECEIVED, handler_a)
    event_bus.subscribe(EventType.ALERT_RECEIVED, handler_b)
    await event_bus.publish(Event(event_type=EventType.ALERT_RECEIVED))

    assert count["a"] == 1
    assert count["b"] == 1


@pytest.mark.asyncio
async def test_unsubscribe(event_bus):
    received = []

    async def handler(event: Event):
        received.append(event)

    event_bus.subscribe(EventType.ALERT_RECEIVED, handler)
    event_bus.unsubscribe(EventType.ALERT_RECEIVED, handler)
    await event_bus.publish(Event(event_type=EventType.ALERT_RECEIVED))

    assert len(received) == 0


@pytest.mark.asyncio
async def test_event_type_filtering(event_bus):
    received = []

    async def handler(event: Event):
        received.append(event)

    event_bus.subscribe(EventType.ALERT_RECEIVED, handler)
    await event_bus.publish(Event(event_type=EventType.INCIDENT_CREATED))

    assert len(received) == 0


@pytest.mark.asyncio
async def test_history(event_bus):
    for i in range(5):
        await event_bus.publish(Event(event_type=EventType.ALERT_RECEIVED, data={"i": i}))

    history = event_bus.get_history(event_type=EventType.ALERT_RECEIVED)
    assert len(history) == 5

    history = event_bus.get_history(limit=3)
    assert len(history) == 3


@pytest.mark.asyncio
async def test_handler_error_doesnt_crash(event_bus):
    async def bad_handler(event: Event):
        raise ValueError("boom")

    received = []

    async def good_handler(event: Event):
        received.append(event)

    event_bus.subscribe(EventType.ALERT_RECEIVED, bad_handler)
    event_bus.subscribe(EventType.ALERT_RECEIVED, good_handler)
    await event_bus.publish(Event(event_type=EventType.ALERT_RECEIVED))

    assert len(received) == 1
