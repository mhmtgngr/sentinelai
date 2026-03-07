"""Centralized notification manager for Sentinel-AI.

Routes alerts and system events to multiple notification channels based on
severity. Supports Teams webhooks, WebSocket push, generic webhooks
(Slack/PagerDuty/Opsgenie), and console logging.

Usage:
    nm = NotificationManager(event_bus)
    nm.load_config("config/notifications.yaml")
    nm.subscribe_events()  # auto-subscribes to critical EventBus events
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)

# Severity ordering for threshold comparison
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ChannelConfig:
    """Configuration for a notification channel."""

    name: str
    enabled: bool = True
    min_severity: str = "low"
    url: str = ""
    url_env: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def resolved_url(self) -> str:
        """Resolve URL from env var or direct config."""
        if self.url_env:
            return os.getenv(self.url_env, self.url)
        return self.url

    def accepts_severity(self, severity: str) -> bool:
        """Check if this channel accepts the given severity level."""
        return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(self.min_severity, 0)


@dataclass
class Notification:
    """A structured notification ready for dispatch."""

    title: str
    message: str
    severity: str = "medium"
    source: str = ""
    timestamp: str = ""
    event_type: str = ""
    ai_analysis: dict[str, Any] | None = None
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    approval_id: str = ""  # For escalation notifications
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "source": self.source,
            "timestamp": self.timestamp or datetime.now(timezone.utc).isoformat(),
            "event_type": self.event_type,
        }
        if self.ai_analysis:
            result["ai_analysis"] = self.ai_analysis
        if self.mitre_techniques:
            result["mitre_techniques"] = self.mitre_techniques
        if self.recommended_actions:
            result["recommended_actions"] = self.recommended_actions
        if self.approval_id:
            result["approval_id"] = self.approval_id
        if self.extra:
            result.update(self.extra)
        return result


class NotificationManager:
    """Routes notifications to multiple channels based on severity.

    Channels:
    - teams_webhook: Microsoft Teams Adaptive Cards
    - websocket: Real-time push to connected dashboard clients
    - console: Structured log output (always available)
    - generic_webhook: POST JSON to any URL (Slack, PagerDuty, etc.)
    """

    def __init__(self, event_bus: EventBus, config: dict[str, Any] | None = None) -> None:
        self.event_bus = event_bus
        self._channels: dict[str, ChannelConfig] = {}
        self._throttle_max: int = 10  # per channel per minute
        self._throttle_counts: dict[str, list[float]] = {}  # channel -> [timestamps]

        # Stats
        self._stats = {
            "total_notifications": 0,
            "notifications_sent": 0,
            "notifications_throttled": 0,
            "channel_stats": {},
        }

        if config:
            self._apply_config(config)

    def load_config(self, config_path: str | Path = "config/notifications.yaml") -> None:
        """Load notification configuration from YAML file."""
        path = Path(config_path)
        if not path.exists():
            logger.info("No notification config found at %s, using defaults", path)
            self._setup_defaults()
            return

        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            self._apply_config(data.get("notifications", {}))
        except Exception:
            logger.exception("Failed to load notification config, using defaults")
            self._setup_defaults()

    def _apply_config(self, config: dict[str, Any]) -> None:
        """Apply notification configuration."""
        channels = config.get("channels", {})

        for name, ch_config in channels.items():
            self._channels[name] = ChannelConfig(
                name=name,
                enabled=ch_config.get("enabled", True),
                min_severity=ch_config.get("min_severity", "low"),
                url=ch_config.get("url", ""),
                url_env=ch_config.get("url_env", ""),
                headers=ch_config.get("headers", {}),
            )

        throttle = config.get("throttle", {})
        self._throttle_max = throttle.get("max_per_channel_per_minute", 10)

        # Ensure console always exists
        if "console" not in self._channels:
            self._channels["console"] = ChannelConfig(name="console", enabled=True, min_severity="low")

        logger.info("Notification manager configured: %d channels", len(self._channels))

    def _setup_defaults(self) -> None:
        """Setup default notification channels."""
        self._channels = {
            "teams_webhook": ChannelConfig(
                name="teams_webhook", enabled=True, min_severity="high", url_env="TEAMS_WEBHOOK_URL",
            ),
            "websocket": ChannelConfig(
                name="websocket", enabled=True, min_severity="low",
            ),
            "console": ChannelConfig(
                name="console", enabled=True, min_severity="low",
            ),
            "generic_webhook": ChannelConfig(
                name="generic_webhook", enabled=False, min_severity="critical", url_env="WEBHOOK_URL",
            ),
        }

    def subscribe_events(self) -> None:
        """Subscribe to critical EventBus events for automatic notification."""
        self.event_bus.subscribe(EventType.THREAT_DETECTED, self._on_threat_detected)
        self.event_bus.subscribe(EventType.ACTION_REQUESTED, self._on_action_requested)
        self.event_bus.subscribe(EventType.ACTION_EXECUTED, self._on_action_executed)
        self.event_bus.subscribe(EventType.ACTION_FAILED, self._on_action_failed)
        self.event_bus.subscribe(EventType.RED_TEAM_CAMPAIGN_COMPLETED, self._on_red_team_complete)
        logger.info("Notification manager subscribed to EventBus events")

    # ───────────── Event Handlers ─────────────

    async def _on_threat_detected(self, event: Event) -> None:
        """Handle THREAT_DETECTED events."""
        data = event.data
        attack_type = data.get("attack_type", "unknown").replace("_", " ").title()
        severity = data.get("severity", "medium")
        source_ip = data.get("source_ip", "unknown")

        notification = Notification(
            title=f"Threat Detected: {attack_type}",
            message=(
                f"{attack_type} attack detected from {source_ip}. "
                f"Severity: {severity.upper()}. "
                f"{data.get('description', '')}"
            ),
            severity=severity,
            source=event.source,
            timestamp=event.timestamp.isoformat(),
            event_type="threat_detected",
            ai_analysis=data.get("ai_analysis"),
            mitre_techniques=data.get("mitre_tactics", []),
            recommended_actions=data.get("recommendations", []),
        )
        await self.notify(notification)

    async def _on_action_requested(self, event: Event) -> None:
        """Handle ACTION_REQUESTED events (escalations needing approval)."""
        data = event.data
        if not data.get("requires_approval"):
            return

        notification = Notification(
            title=f"Approval Required: {data.get('action', 'unknown')}",
            message=(
                f"Action '{data.get('action', 'unknown')}' on target "
                f"'{data.get('target', 'unknown')}' requires human approval. "
                f"Confidence: {data.get('confidence', 0):.0%}. "
                f"Reason: {data.get('escalation_reason', 'policy')}"
            ),
            severity=data.get("severity", "high"),
            source=event.source,
            timestamp=event.timestamp.isoformat(),
            event_type="approval_needed",
            approval_id=data.get("decision_id", ""),
        )
        await self.notify(notification)

    async def _on_action_executed(self, event: Event) -> None:
        """Handle ACTION_EXECUTED events."""
        data = event.data
        notification = Notification(
            title=f"Action Executed: {data.get('action', 'unknown')}",
            message=(
                f"Action '{data.get('action', 'unknown')}' executed successfully "
                f"on target '{data.get('target', 'unknown')}'."
            ),
            severity="medium",
            source=event.source,
            timestamp=event.timestamp.isoformat(),
            event_type="action_executed",
        )
        await self.notify(notification)

    async def _on_action_failed(self, event: Event) -> None:
        """Handle ACTION_FAILED events."""
        data = event.data
        notification = Notification(
            title=f"Action Failed: {data.get('action', 'unknown')}",
            message=(
                f"Action '{data.get('action', 'unknown')}' FAILED "
                f"on target '{data.get('target', 'unknown')}'. "
                f"Error: {data.get('error', 'unknown')}"
            ),
            severity="high",
            source=event.source,
            timestamp=event.timestamp.isoformat(),
            event_type="action_failed",
        )
        await self.notify(notification)

    async def _on_red_team_complete(self, event: Event) -> None:
        """Handle RED_TEAM_CAMPAIGN_COMPLETED events."""
        data = event.data
        notification = Notification(
            title=f"Red Team Campaign Complete: {data.get('campaign_name', 'unknown')}",
            message=(
                f"Campaign completed. "
                f"Techniques tested: {data.get('techniques_tested', 0)}. "
                f"Detection rate: {data.get('detection_rate', 0):.0%}."
            ),
            severity="medium",
            source=event.source,
            timestamp=event.timestamp.isoformat(),
            event_type="red_team_complete",
        )
        await self.notify(notification)

    # ───────────── Core Dispatch ─────────────

    async def notify(self, notification: Notification) -> dict[str, bool]:
        """Dispatch notification to all eligible channels."""
        self._stats["total_notifications"] += 1
        results: dict[str, bool] = {}

        for name, channel in self._channels.items():
            if not channel.enabled:
                continue
            if not channel.accepts_severity(notification.severity):
                continue
            if not self._check_throttle(name):
                self._stats["notifications_throttled"] += 1
                results[name] = False
                continue

            try:
                success = await self._send_to_channel(name, channel, notification)
                results[name] = success
                if success:
                    self._stats["notifications_sent"] += 1
                    self._record_throttle(name)

                # Track per-channel stats
                ch_stats = self._stats["channel_stats"].setdefault(name, {"sent": 0, "failed": 0})
                if success:
                    ch_stats["sent"] += 1
                else:
                    ch_stats["failed"] += 1
            except Exception:
                logger.exception("Failed to send notification to channel: %s", name)
                results[name] = False

        return results

    async def _send_to_channel(self, name: str, channel: ChannelConfig, notification: Notification) -> bool:
        """Send notification to a specific channel."""
        if name == "console":
            return self._send_console(notification)
        elif name == "teams_webhook":
            return await self._send_teams(channel, notification)
        elif name == "websocket":
            return await self._send_websocket(notification)
        elif name == "generic_webhook":
            return await self._send_generic_webhook(channel, notification)
        else:
            logger.warning("Unknown notification channel: %s", name)
            return False

    def _send_console(self, notification: Notification) -> bool:
        """Log notification to console."""
        severity = notification.severity.upper()
        log_func = logger.critical if severity == "CRITICAL" else (
            logger.warning if severity in ("HIGH", "MEDIUM") else logger.info
        )
        log_func(
            "[ALERT] [%s] %s — %s (source=%s)",
            severity, notification.title, notification.message, notification.source,
        )
        return True

    async def _send_teams(self, channel: ChannelConfig, notification: Notification) -> bool:
        """Send notification via Teams webhook (Adaptive Card)."""
        url = channel.resolved_url
        if not url:
            logger.debug("Teams webhook URL not configured, skipping")
            return False

        color_map = {"critical": "FF0000", "high": "FF6600", "medium": "FFAA00", "low": "00CC00", "info": "0078D4"}
        body_items: list[dict[str, Any]] = [
            {
                "type": "TextBlock",
                "text": f"Sentinel-AI: {notification.title}",
                "weight": "bolder",
                "size": "medium",
                "color": "attention" if notification.severity in ("critical", "high") else "default",
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Severity", "value": notification.severity.upper()},
                    {"title": "Time", "value": notification.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")},
                    {"title": "Source", "value": notification.source or "sentinel-ai"},
                ],
            },
            {
                "type": "TextBlock",
                "text": notification.message,
                "wrap": True,
            },
        ]

        # Add AI analysis if available
        if notification.ai_analysis:
            ai = notification.ai_analysis
            body_items.append({
                "type": "TextBlock",
                "text": f"**AI Analysis:** {ai.get('explanation', '')}",
                "wrap": True,
            })

        # Add recommended actions
        if notification.recommended_actions:
            actions_text = ", ".join(notification.recommended_actions[:5])
            body_items.append({
                "type": "TextBlock",
                "text": f"**Recommended:** {actions_text}",
                "wrap": True,
            })

        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body_items,
                },
            }],
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, json=card)
                return resp.status_code in (200, 202)
        except Exception:
            logger.exception("Failed to send Teams notification")
            return False

    async def _send_websocket(self, notification: Notification) -> bool:
        """Send notification via WebSocket broadcast."""
        try:
            from src.api.websocket import manager as ws_manager

            event = Event(
                event_type=EventType.THREAT_DETECTED,
                data={
                    "notification": notification.to_dict(),
                    "notification_type": notification.event_type,
                },
                source="notification_manager",
            )
            await ws_manager.broadcast(event)
            return True
        except Exception:
            logger.debug("WebSocket broadcast failed (no active connections?)")
            return False

    async def _send_generic_webhook(self, channel: ChannelConfig, notification: Notification) -> bool:
        """Send notification via generic webhook (Slack, PagerDuty, etc.)."""
        url = channel.resolved_url
        if not url:
            logger.debug("Generic webhook URL not configured, skipping")
            return False

        payload = notification.to_dict()

        headers = {"Content-Type": "application/json"}
        headers.update(channel.headers)

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
                return resp.status_code in (200, 201, 202, 204)
        except Exception:
            logger.exception("Failed to send generic webhook notification")
            return False

    # ───────────── Throttling ─────────────

    def _check_throttle(self, channel_name: str) -> bool:
        """Check if channel is within throttle limit."""
        now = time.time()
        timestamps = self._throttle_counts.get(channel_name, [])
        timestamps = [t for t in timestamps if now - t < 60]
        self._throttle_counts[channel_name] = timestamps
        return len(timestamps) < self._throttle_max

    def _record_throttle(self, channel_name: str) -> None:
        """Record a notification send for throttling."""
        if channel_name not in self._throttle_counts:
            self._throttle_counts[channel_name] = []
        self._throttle_counts[channel_name].append(time.time())

    # ───────────── Stats ─────────────

    def get_stats(self) -> dict[str, Any]:
        """Return notification manager statistics."""
        return {
            **self._stats,
            "channels": {
                name: {
                    "enabled": ch.enabled,
                    "min_severity": ch.min_severity,
                    "has_url": bool(ch.resolved_url) if ch.name not in ("console", "websocket") else True,
                }
                for name, ch in self._channels.items()
            },
            "throttle_limit": self._throttle_max,
        }
