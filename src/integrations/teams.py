"""Microsoft Teams integration — sends adaptive cards and processes responses."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.core.config import settings
from src.core.event_bus import event_bus, DECISION_NEEDED, DECISION_MADE
from src.core.models import (
    Alert,
    Decision,
    DecisionAction,
    Severity,
    TriageResult,
)

logger = logging.getLogger(__name__)

# Severity → color mapping for adaptive cards
SEVERITY_COLORS: dict[str, str] = {
    "critical": "attention",
    "high": "attention",
    "medium": "warning",
    "low": "good",
}


class TeamsIntegration:
    """Send adaptive cards to Teams channels and process analyst responses."""

    def __init__(self) -> None:
        self._pending_decisions: dict[str, dict[str, Any]] = {}
        event_bus.subscribe(DECISION_NEEDED, self.send_decision_card)

    async def send_decision_card(self, data: dict) -> None:
        """Send an adaptive card to Teams requesting analyst decision."""
        alert = Alert(**data["alert"])
        triage = TriageResult(**data["triage"])

        card = self._build_decision_card(alert, triage)
        message_id = await self._send_card(card)

        if message_id:
            self._pending_decisions[alert.id] = {
                "alert": data["alert"],
                "triage": data["triage"],
                "teams_message_id": message_id,
            }
            logger.info(
                "Decision card sent to Teams for alert %s (message: %s)",
                alert.id, message_id,
            )

    async def send_notification(self, title: str, message: str, severity: str = "medium") -> None:
        """Send a simple notification card to Teams."""
        card = self._build_notification_card(title, message, severity)
        await self._send_card(card)

    async def send_education_notification(
        self, user_name: str, alert_title: str, topics: list[str]
    ) -> None:
        """Notify the Teams channel that user education was sent."""
        topics_text = ", ".join(t.replace("_", " ").title() for t in topics)
        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "User Education Sent",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "good",
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "User", "value": user_name},
                                {"title": "Triggered By", "value": alert_title},
                                {"title": "Topics", "value": topics_text},
                            ],
                        },
                    ],
                },
            }],
        }
        await self._send_card(card)

    async def process_response(self, response_data: dict) -> Decision | None:
        """Process a Teams adaptive card action response.

        Called by the webhook endpoint when Teams sends a callback.
        """
        alert_id = response_data.get("alert_id")
        action_value = response_data.get("action")
        analyst = response_data.get("analyst", "teams_user")
        reason = response_data.get("reason", "")

        if not alert_id or alert_id not in self._pending_decisions:
            logger.warning("Received Teams response for unknown alert: %s", alert_id)
            return None

        pending = self._pending_decisions.pop(alert_id)
        alert_data = pending["alert"]

        try:
            decision_action = DecisionAction(action_value)
        except ValueError:
            decision_action = DecisionAction.CUSTOM

        decision = Decision(
            alert_id=alert_id,
            action=decision_action,
            decided_by=analyst,
            reason=reason,
            custom_action=action_value if decision_action == DecisionAction.CUSTOM else None,
            teams_message_id=pending.get("teams_message_id"),
        )

        await event_bus.publish(DECISION_MADE, {
            "decision": decision.model_dump(mode="json"),
            "alert": alert_data,
        })

        # Send confirmation back to Teams
        await self.send_notification(
            title="Decision Recorded",
            message=(
                f"Alert: {alert_data.get('title', alert_id)}\n"
                f"Action: {decision.action.value}\n"
                f"Decided by: {analyst}"
            ),
            severity="good",
        )

        return decision

    async def handle_timeout(self, alert_id: str) -> None:
        """Handle expired decision — auto-escalate if no response within timeout."""
        if alert_id not in self._pending_decisions:
            return

        pending = self._pending_decisions.pop(alert_id)
        logger.warning("Teams decision timeout for alert %s — auto-escalating", alert_id)

        decision = Decision(
            alert_id=alert_id,
            action=DecisionAction.ESCALATE,
            decided_by="system_timeout",
            reason=f"No response within {settings.teams_decision_timeout_minutes} minutes",
        )

        await event_bus.publish(DECISION_MADE, {
            "decision": decision.model_dump(mode="json"),
            "alert": pending["alert"],
        })

        await self.send_notification(
            title="Decision Timeout — Auto-Escalated",
            message=f"Alert {alert_id} was auto-escalated due to no response.",
            severity="attention",
        )

    def _build_decision_card(self, alert: Alert, triage: TriageResult) -> dict:
        """Build a Teams adaptive card with action buttons for analyst decision."""
        color = SEVERITY_COLORS.get(alert.severity.value, "default")
        actions_text = ", ".join(
            a.replace("_", " ").title() for a in triage.recommended_actions
        )
        callback_url = f"{settings.api_base_url}/api/v1/teams/callback"

        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"SENTINEL-AI Alert — {alert.severity.value.upper()}",
                            "weight": "Bolder",
                            "size": "Large",
                            "color": color,
                        },
                        {
                            "type": "TextBlock",
                            "text": alert.title,
                            "weight": "Bolder",
                            "size": "Medium",
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Alert ID", "value": alert.id},
                                {"title": "Category",
                                 "value": alert.category.value.replace("_", " ").title()},
                                {"title": "Severity", "value": alert.severity.value.upper()},
                                {"title": "Source", "value": alert.source or "Unknown"},
                                {"title": "Affected User",
                                 "value": alert.affected_user or "N/A"},
                                {"title": "Endpoint",
                                 "value": alert.affected_endpoint or "N/A"},
                                {"title": "Source IP",
                                 "value": alert.affected_ip or "N/A"},
                                {"title": "Recommended",
                                 "value": actions_text},
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": triage.summary,
                            "wrap": True,
                            "spacing": "Medium",
                        },
                        {
                            "type": "TextBlock",
                            "text": alert.description,
                            "wrap": True,
                            "isSubtle": True,
                            "spacing": "Small",
                        },
                        {
                            "type": "Input.Text",
                            "id": "reason",
                            "placeholder": "Add notes (optional)",
                            "isMultiline": True,
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.Http",
                            "title": "Approve Remediation",
                            "method": "POST",
                            "url": callback_url,
                            "body": (
                                '{"alert_id":"' + alert.id + '",'
                                '"action":"approve_remediate",'
                                '"reason":"{{reason.value}}"}'
                            ),
                            "style": "positive",
                        },
                        {
                            "type": "Action.Http",
                            "title": "Isolate Endpoint",
                            "method": "POST",
                            "url": callback_url,
                            "body": (
                                '{"alert_id":"' + alert.id + '",'
                                '"action":"isolate_endpoint",'
                                '"reason":"{{reason.value}}"}'
                            ),
                        },
                        {
                            "type": "Action.Http",
                            "title": "Block IP",
                            "method": "POST",
                            "url": callback_url,
                            "body": (
                                '{"alert_id":"' + alert.id + '",'
                                '"action":"block_ip",'
                                '"reason":"{{reason.value}}"}'
                            ),
                        },
                        {
                            "type": "Action.Http",
                            "title": "Disable Account",
                            "method": "POST",
                            "url": callback_url,
                            "body": (
                                '{"alert_id":"' + alert.id + '",'
                                '"action":"disable_account",'
                                '"reason":"{{reason.value}}"}'
                            ),
                            "style": "destructive",
                        },
                        {
                            "type": "Action.Http",
                            "title": "Educate User",
                            "method": "POST",
                            "url": callback_url,
                            "body": (
                                '{"alert_id":"' + alert.id + '",'
                                '"action":"educate_user",'
                                '"reason":"{{reason.value}}"}'
                            ),
                        },
                        {
                            "type": "Action.Http",
                            "title": "Ignore",
                            "method": "POST",
                            "url": callback_url,
                            "body": (
                                '{"alert_id":"' + alert.id + '",'
                                '"action":"ignore",'
                                '"reason":"{{reason.value}}"}'
                            ),
                        },
                    ],
                },
            }],
        }

    def _build_notification_card(
        self, title: str, message: str, severity: str
    ) -> dict:
        color = SEVERITY_COLORS.get(severity, "default")
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": title,
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": color,
                        },
                        {
                            "type": "TextBlock",
                            "text": message,
                            "wrap": True,
                        },
                    ],
                },
            }],
        }

    async def _send_card(self, card: dict) -> str | None:
        """POST an adaptive card to the Teams incoming webhook."""
        if not settings.teams_webhook_url:
            logger.warning("Teams webhook URL not configured — skipping card send")
            return None
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(settings.teams_webhook_url, json=card)
                resp.raise_for_status()
                return resp.headers.get("x-]]message-id", resp.text[:64])
        except httpx.HTTPError:
            logger.exception("Failed to send Teams card")
            return None
