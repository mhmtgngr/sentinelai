"""Central AI Brain — multi-agent coordinator for Sentinel-AI."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from src.core.config import SentinelConfig
from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


class SentinelBrain:
    """Orchestrates all agents, manages the heartbeat loop, and coordinates responses."""

    def __init__(self, config: SentinelConfig, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus
        self._agents: dict[str, Any] = {}
        self._adapters: dict[str, Any] = {}
        self._running = False
        self._heartbeat_task: asyncio.Task | None = None

    def register_agent(self, name: str, agent: Any) -> None:
        self._agents[name] = agent
        logger.info("Registered agent: %s", name)

    def register_adapter(self, name: str, adapter: Any) -> None:
        self._adapters[name] = adapter
        logger.info("Registered adapter: %s", name)

    async def start(self) -> None:
        """Start the brain: connect adapters, initialize agents, begin heartbeat."""
        logger.info("Starting Sentinel-AI Brain...")
        self._running = True

        # Initialize all adapters
        for name, adapter in self._adapters.items():
            try:
                await adapter.connect()
                await self.event_bus.publish(Event(
                    event_type=EventType.ADAPTER_CONNECTED,
                    data={"adapter": name},
                    source="brain",
                ))
            except Exception:
                logger.exception("Failed to connect adapter: %s", name)

        # Initialize all agents
        for name, agent in self._agents.items():
            try:
                await agent.initialize()
            except Exception:
                logger.exception("Failed to initialize agent: %s", name)

        # Subscribe to key events
        self.event_bus.subscribe(EventType.ALERT_RECEIVED, self._handle_alert)
        self.event_bus.subscribe(EventType.THREAT_DETECTED, self._handle_threat)
        self.event_bus.subscribe(EventType.ACTION_REQUESTED, self._handle_action_request)

        # Start heartbeat
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Sentinel-AI Brain started with %d agents and %d adapters",
                     len(self._agents), len(self._adapters))

    async def stop(self) -> None:
        """Gracefully stop the brain."""
        logger.info("Stopping Sentinel-AI Brain...")
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        for name, adapter in self._adapters.items():
            try:
                await adapter.disconnect()
            except Exception:
                logger.exception("Error disconnecting adapter: %s", name)

        logger.info("Sentinel-AI Brain stopped")

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat that triggers proactive scanning."""
        while self._running:
            try:
                await self.event_bus.publish(Event(
                    event_type=EventType.HEARTBEAT,
                    data={"timestamp": datetime.now(timezone.utc).isoformat()},
                    source="brain",
                ))

                # Collect events from all adapters
                await self._collect_events()

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in heartbeat loop")

            await asyncio.sleep(self.config.heartbeat_interval)

    async def _collect_events(self) -> None:
        """Pull events from all connected adapters."""
        for name, adapter in self._adapters.items():
            try:
                events = await adapter.get_events()
                for event_data in events:
                    await self.event_bus.publish(Event(
                        event_type=EventType.ALERT_RECEIVED,
                        data=event_data,
                        source=name,
                    ))
            except Exception:
                logger.exception("Error collecting events from adapter: %s", name)

    async def _handle_alert(self, event: Event) -> None:
        """Route incoming alerts to the triage agent."""
        triage = self._agents.get("triage")
        if triage:
            await triage.process(event)

    async def _handle_threat(self, event: Event) -> None:
        """Route detected threats to the incident responder."""
        responder = self._agents.get("incident_responder")
        if responder:
            await responder.process(event)

    async def _handle_action_request(self, event: Event) -> None:
        """Handle action requests — apply human-in-the-loop for critical actions."""
        severity = event.data.get("severity", "low")
        if severity in ("critical", "high"):
            logger.info("Critical action requires approval: %s", event.data.get("action"))
            await self.event_bus.publish(Event(
                event_type=EventType.ACTION_APPROVED,
                data={**event.data, "auto_approved": False, "pending_approval": True},
                source="brain",
            ))
        else:
            # Auto-approve low/medium severity actions
            await self.event_bus.publish(Event(
                event_type=EventType.ACTION_APPROVED,
                data={**event.data, "auto_approved": True},
                source="brain",
            ))

    def get_status(self) -> dict[str, Any]:
        """Return current system status."""
        return {
            "running": self._running,
            "agents": list(self._agents.keys()),
            "adapters": list(self._adapters.keys()),
            "event_history_size": len(self.event_bus._history),
        }
