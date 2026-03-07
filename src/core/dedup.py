"""Alert deduplication engine — reduces alert fatigue by grouping similar alerts."""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from src.core.config import settings
from src.core.models import Alert, Severity

logger = logging.getLogger(__name__)


class DedupEntry:
    """Tracks a group of deduplicated alerts."""

    __slots__ = ("fingerprint", "first_seen", "last_seen", "count", "alert_ids", "severity")

    def __init__(self, fingerprint: str, alert: Alert) -> None:
        self.fingerprint = fingerprint
        self.first_seen = alert.timestamp
        self.last_seen = alert.timestamp
        self.count = 1
        self.alert_ids = [alert.id]
        self.severity = alert.severity

    def update(self, alert: Alert) -> None:
        self.last_seen = alert.timestamp
        self.count += 1
        self.alert_ids.append(alert.id)
        if _severity_rank(alert.severity) > _severity_rank(self.severity):
            self.severity = alert.severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "alert_ids": self.alert_ids,
            "severity": self.severity.value,
        }


def _severity_rank(sev: Severity) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}[sev.value]


class AlertDeduplicator:
    """Deduplicates alerts within a configurable time window.

    Fingerprint is computed from: source + category + affected_user + affected_endpoint + title_stem.
    """

    def __init__(self, window_seconds: int | None = None) -> None:
        self._window = window_seconds or settings.alert_dedup_window_seconds
        self._entries: dict[str, DedupEntry] = {}
        self._suppressed_count = 0
        self._total_count = 0

    def fingerprint(self, alert: Alert) -> str:
        """Compute a dedup fingerprint for an alert."""
        title_stem = alert.title.lower().strip()[:80]
        raw = "|".join([
            alert.source,
            alert.category.value,
            alert.affected_user or "",
            alert.affected_endpoint or "",
            title_stem,
        ])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def check(self, alert: Alert) -> tuple[bool, DedupEntry]:
        """Check if an alert is a duplicate.

        Returns (is_duplicate, entry). If is_duplicate is True, the alert
        was already seen within the dedup window and should be suppressed.
        """
        self._total_count += 1
        self._cleanup_expired()

        fp = self.fingerprint(alert)
        existing = self._entries.get(fp)

        if existing is not None:
            window_end = existing.last_seen + timedelta(seconds=self._window)
            if alert.timestamp <= window_end:
                existing.update(alert)
                self._suppressed_count += 1
                logger.info(
                    "Dedup: suppressed alert %s (fingerprint %s, count=%d)",
                    alert.id, fp, existing.count,
                )
                return True, existing

        entry = DedupEntry(fp, alert)
        self._entries[fp] = entry
        return False, entry

    def _cleanup_expired(self) -> None:
        """Remove entries older than 2x the dedup window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._window * 2)
        expired = [fp for fp, e in self._entries.items() if e.last_seen < cutoff]
        for fp in expired:
            del self._entries[fp]

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total_alerts": self._total_count,
            "suppressed": self._suppressed_count,
            "active_groups": len(self._entries),
            "suppression_rate": (
                round(self._suppressed_count / self._total_count, 3)
                if self._total_count > 0 else 0.0
            ),
        }
