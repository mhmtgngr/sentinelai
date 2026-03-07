"""In-process async event bus for Sentinel-AI.

Topic-based pub/sub using asyncio queues.
Phase 2 will replace this with Redis Streams or NATS JetStream.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

Subscriber = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


@dataclass
class Event:
    """An event published to the bus."""

    topic: str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: str = ""


class EventBus:
    """In-process async event bus with topic-based pub/sub.

    Topics:
        alert.new, alert.triaged, threat.confirmed,
        incident.created, action.executed, action.pending_approval,
        adapter.health, investigation.requested
    """

    def __init__(self, max_queue_size: int = 10000) -> None:
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self._running = False
        self._task: asyncio.Task[None] | None = None

    def subscribe(self, topic: str, callback: Subscriber) -> None:
        """Register a callback for a topic."""
        self._subscribers[topic].append(callback)
        logger.debug("Subscriber registered for topic '%s'", topic)

    def unsubscribe(self, topic: str, callback: Subscriber) -> None:
        """Remove a callback from a topic."""
        if callback in self._subscribers[topic]:
            self._subscribers[topic].remove(callback)

    async def publish(self, topic: str, data: dict[str, Any], correlation_id: str = "") -> None:
        """Publish an event to a topic."""
        event = Event(topic=topic, data=data, correlation_id=correlation_id)
        await self._queue.put(event)
        logger.debug("Event published to '%s' (queue depth: %d)", topic, self._queue.qsize())

    async def start(self) -> None:
        """Start the event bus consumer loop."""
        self._running = True
        self._task = asyncio.create_task(self._consume())
        logger.info("Event bus started")

    async def stop(self) -> None:
        """Stop the event bus gracefully."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Event bus stopped")

    async def _consume(self) -> None:
        """Main consumer loop — dispatches events to subscribers."""
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            subscribers = self._subscribers.get(event.topic, [])
            if not subscribers:
                logger.debug("No subscribers for topic '%s'", event.topic)
                continue

            for callback in subscribers:
                try:
                    await callback(event.data)
                except Exception:
                    logger.exception(
                        "Subscriber error on topic '%s'",
                        event.topic,
                    )

    @property
    def queue_depth(self) -> int:
        """Current number of unprocessed events."""
        return self._queue.qsize()

    @property
    def subscriber_count(self) -> dict[str, int]:
        """Number of subscribers per topic."""
        return {topic: len(subs) for topic, subs in self._subscribers.items()}
