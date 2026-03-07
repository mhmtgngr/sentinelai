"""Async event bus for internal pub/sub between components."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

# Event handler type: async callable that takes event data
EventHandler = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class EventBus:
    """Simple async event bus for decoupled component communication."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        self._handlers[event_type].append(handler)
        logger.debug("Subscribed %s to event '%s'", handler.__qualname__, event_type)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        self._handlers[event_type].remove(handler)

    async def publish(self, event_type: str, data: dict[str, Any] | None = None) -> None:
        data = data or {}
        handlers = self._handlers.get(event_type, [])
        logger.info("Publishing event '%s' to %d handler(s)", event_type, len(handlers))
        tasks = [asyncio.create_task(self._safe_call(h, data)) for h in handlers]
        if tasks:
            await asyncio.gather(*tasks)

    async def _safe_call(self, handler: EventHandler, data: dict[str, Any]) -> None:
        try:
            await handler(data)
        except Exception:
            logger.exception("Handler %s failed for event data: %s", handler.__qualname__, data)


# Singleton event bus
event_bus = EventBus()

# ── Event type constants ──
ALERT_RECEIVED = "alert.received"
ALERT_TRIAGED = "alert.triaged"
DECISION_NEEDED = "decision.needed"
DECISION_MADE = "decision.made"
SOAR_ACTION_EXECUTED = "soar.action.executed"
EDUCATION_SENT = "education.sent"
TEAMS_RESPONSE_RECEIVED = "teams.response.received"
