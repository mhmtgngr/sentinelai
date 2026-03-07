"""Education manager — listens for triage events and sends targeted training."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.core.event_bus import (
    event_bus,
    ALERT_TRIAGED,
    DECISION_MADE,
    EDUCATION_SENT,
)
from src.core.models import (
    Alert,
    AlertCategory,
    Decision,
    DecisionAction,
    TriageResult,
    UserEducation,
)
from src.education.content import get_education_html, get_category_topics
from src.integrations.email import EmailService
from src.integrations.teams import TeamsIntegration

logger = logging.getLogger(__name__)


class EducationManager:
    """Automatically sends security education to affected users based on alert type."""

    def __init__(
        self,
        email_service: EmailService,
        teams: TeamsIntegration,
    ) -> None:
        self._email = email_service
        self._teams = teams
        self._sent_log: list[UserEducation] = []
        event_bus.subscribe(ALERT_TRIAGED, self.handle_triaged_alert)
        event_bus.subscribe(DECISION_MADE, self.handle_decision)

    async def handle_triaged_alert(self, data: dict) -> None:
        """Auto-send education for low/medium severity alerts with education flag."""
        triage = TriageResult(**data["triage"])
        if not triage.education_needed or triage.requires_human_decision:
            return
        alert = Alert(**data["alert"])
        await self.send_education(alert, triage.education_topics)

    async def handle_decision(self, data: dict) -> None:
        """Send education when a Teams analyst chooses 'educate_user'."""
        decision = Decision(**data["decision"])
        if decision.action != DecisionAction.EDUCATE_USER:
            return
        alert = Alert(**data["alert"])
        topics = get_category_topics(alert.category)
        await self.send_education(alert, topics)

    async def send_education(
        self, alert: Alert, topics: list[str] | None = None
    ) -> UserEducation | None:
        """Send education email and notify Teams channel."""
        if not alert.affected_user:
            logger.warning("No affected user for alert %s — skipping education", alert.id)
            return None

        if not topics:
            topics = get_category_topics(alert.category)

        education_html = get_education_html(topics)
        user_email = alert.affected_user
        user_name = user_email.split("@")[0].replace(".", " ").title()

        success = await self._email.send_education_email(
            to=user_email,
            user_name=user_name,
            alert_category=alert.category.value,
            education_html=education_html,
        )

        record = UserEducation(
            alert_id=alert.id,
            user_email=user_email,
            category=alert.category,
            topics=topics,
            content_sent=education_html,
            sent_at=datetime.now(timezone.utc) if success else None,
            sent_via="email",
        )
        self._sent_log.append(record)

        await self._teams.send_education_notification(
            user_name=user_name,
            alert_title=alert.title,
            topics=topics,
        )

        await event_bus.publish(EDUCATION_SENT, {
            "education": record.model_dump(mode="json"),
        })

        logger.info(
            "Education sent to %s for alert %s (topics: %s)",
            user_email, alert.id, ", ".join(topics),
        )
        return record
