"""Tests for the async event bus."""

from __future__ import annotations

import asyncio

import pytest

from src.core.event_bus import EventBus


class TestEventBus:
    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self) -> None:
        bus = EventBus()
        received: list[dict] = []

        async def handler(data: dict) -> None:
            received.append(data)

        bus.subscribe("test.topic", handler)
        await bus.start()

        await bus.publish("test.topic", {"key": "value"})
        await asyncio.sleep(0.1)  # Let consumer process

        await bus.stop()
        assert len(received) == 1
        assert received[0]["key"] == "value"

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self) -> None:
        bus = EventBus()
        received_a: list[dict] = []
        received_b: list[dict] = []

        async def handler_a(data: dict) -> None:
            received_a.append(data)

        async def handler_b(data: dict) -> None:
            received_b.append(data)

        bus.subscribe("test.topic", handler_a)
        bus.subscribe("test.topic", handler_b)
        await bus.start()

        await bus.publish("test.topic", {"msg": "hello"})
        await asyncio.sleep(0.1)

        await bus.stop()
        assert len(received_a) == 1
        assert len(received_b) == 1

    @pytest.mark.asyncio
    async def test_topic_isolation(self) -> None:
        bus = EventBus()
        received: list[dict] = []

        async def handler(data: dict) -> None:
            received.append(data)

        bus.subscribe("topic.a", handler)
        await bus.start()

        await bus.publish("topic.b", {"should": "not_receive"})
        await asyncio.sleep(0.1)

        await bus.stop()
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_unsubscribe(self) -> None:
        bus = EventBus()
        received: list[dict] = []

        async def handler(data: dict) -> None:
            received.append(data)

        bus.subscribe("test.topic", handler)
        bus.unsubscribe("test.topic", handler)
        await bus.start()

        await bus.publish("test.topic", {"msg": "hello"})
        await asyncio.sleep(0.1)

        await bus.stop()
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_queue_depth(self) -> None:
        bus = EventBus()
        assert bus.queue_depth == 0

    @pytest.mark.asyncio
    async def test_subscriber_count(self) -> None:
        bus = EventBus()

        async def handler(data: dict) -> None:
            pass

        bus.subscribe("a", handler)
        bus.subscribe("a", handler)
        bus.subscribe("b", handler)
        assert bus.subscriber_count == {"a": 2, "b": 1}

    @pytest.mark.asyncio
    async def test_subscriber_error_doesnt_crash_bus(self) -> None:
        bus = EventBus()
        received: list[dict] = []

        async def bad_handler(data: dict) -> None:
            raise ValueError("boom")

        async def good_handler(data: dict) -> None:
            received.append(data)

        bus.subscribe("test", bad_handler)
        bus.subscribe("test", good_handler)
        await bus.start()

        await bus.publish("test", {"msg": "hello"})
        await asyncio.sleep(0.1)

        await bus.stop()
        assert len(received) == 1  # Good handler still got the event
