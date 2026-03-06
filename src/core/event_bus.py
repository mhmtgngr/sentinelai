"""Internal event pub/sub system for Sentinel-AI."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine
from uuid import uuid4

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    # Alert lifecycle
    ALERT_RECEIVED = "alert.received"
    ALERT_TRIAGED = "alert.triaged"
    ALERT_ESCALATED = "alert.escalated"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_FALSE_POSITIVE = "alert.false_positive"

    # Incident lifecycle
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    INCIDENT_CLOSED = "incident.closed"

    # Threat hunting
    THREAT_DETECTED = "threat.detected"
    THREAT_HUNT_STARTED = "threat.hunt.started"
    THREAT_HUNT_COMPLETED = "threat.hunt.completed"

    # Response actions
    ACTION_REQUESTED = "action.requested"
    ACTION_APPROVED = "action.approved"
    ACTION_EXECUTED = "action.executed"
    ACTION_FAILED = "action.failed"

    # System
    HEARTBEAT = "system.heartbeat"
    ADAPTER_CONNECTED = "adapter.connected"
    ADAPTER_DISCONNECTED = "adapter.disconnected"
    ANOMALY_DETECTED = "anomaly.detected"

    # Learning
    FEEDBACK_RECEIVED = "learning.feedback"
    MODEL_UPDATED = "learning.model_updated"


@dataclass
class Event:
    event_type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


Callback = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """Async pub/sub event bus for internal communication between agents and components."""

    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[Callback]] = {}
        self._history: list[Event] = []
        self._max_history = 10_000

    def subscribe(self, event_type: EventType, callback: Callback) -> None:
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def unsubscribe(self, event_type: EventType, callback: Callback) -> None:
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type] if cb != callback
            ]

    async def publish(self, event: Event) -> None:
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        callbacks = self._subscribers.get(event.event_type, [])
        if not callbacks:
            return

        tasks = [asyncio.create_task(self._safe_call(cb, event)) for cb in callbacks]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_call(self, callback: Callback, event: Event) -> None:
        try:
            await callback(event)
        except Exception:
            logger.exception("Error in event handler for %s", event.event_type)

    def get_history(
        self,
        event_type: EventType | None = None,
        limit: int = 100,
    ) -> list[Event]:
        events = self._history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]
