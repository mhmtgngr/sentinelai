"""Audit trail — immutable log of all autonomous decisions and actions."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AuditEntry(BaseModel):
    """A single audit log entry."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    alert_id: str = ""
    actor: str = "system"
    action: str = ""
    detail: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class AuditTrail:
    """Append-only audit log for compliance and forensic review."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def log(
        self,
        event_type: str,
        alert_id: str = "",
        actor: str = "system",
        action: str = "",
        detail: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            event_type=event_type,
            alert_id=alert_id,
            actor=actor,
            action=action,
            detail=detail,
            metadata=metadata or {},
        )
        self._entries.append(entry)
        logger.info(
            "AUDIT [%s] alert=%s actor=%s action=%s: %s",
            event_type, alert_id, actor, action, detail,
        )
        return entry

    def log_alert_ingested(self, alert_id: str, title: str, source: str) -> AuditEntry:
        return self.log(
            event_type="alert.ingested",
            alert_id=alert_id,
            action="ingest",
            detail=f"Alert ingested: {title} from {source}",
        )

    def log_triage(
        self, alert_id: str, category: str, severity: str, autonomous: bool
    ) -> AuditEntry:
        return self.log(
            event_type="alert.triaged",
            alert_id=alert_id,
            actor="triage_agent",
            action="triage",
            detail=f"Classified as {category} [{severity}], autonomous={autonomous}",
        )

    def log_decision(
        self, alert_id: str, action: str, decided_by: str, reason: str
    ) -> AuditEntry:
        return self.log(
            event_type="decision.made",
            alert_id=alert_id,
            actor=decided_by,
            action=action,
            detail=reason,
        )

    def log_soar_action(
        self, alert_id: str, action_type: str, target: str, status: str, result: str
    ) -> AuditEntry:
        return self.log(
            event_type="soar.executed",
            alert_id=alert_id,
            actor="soar_engine",
            action=action_type,
            detail=f"target={target} status={status}: {result}",
        )

    def log_dedup_suppressed(self, alert_id: str, fingerprint: str, count: int) -> AuditEntry:
        return self.log(
            event_type="alert.deduplicated",
            alert_id=alert_id,
            action="suppress",
            detail=f"Duplicate suppressed (fingerprint={fingerprint}, group_count={count})",
        )

    def log_enrichment(
        self, alert_id: str, matched_count: int, risk_score: float
    ) -> AuditEntry:
        return self.log(
            event_type="alert.enriched",
            alert_id=alert_id,
            actor="threat_intel",
            action="enrich",
            detail=f"Matched {matched_count} indicator(s), risk_score={risk_score:.2f}",
        )

    def get_entries(
        self,
        alert_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        entries = self._entries
        if alert_id:
            entries = [e for e in entries if e.alert_id == alert_id]
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]
        return list(reversed(entries[-limit:]))

    @property
    def total_entries(self) -> int:
        return len(self._entries)
