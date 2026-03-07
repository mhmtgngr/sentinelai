"""Tests for alert deduplication engine."""

from datetime import datetime, timezone, timedelta

from src.core.dedup import AlertDeduplicator
from src.core.models import Alert, AlertCategory, Severity


def test_first_alert_not_duplicate():
    dedup = AlertDeduplicator(window_seconds=300)
    alert = Alert(title="Phishing email", source="email_gateway",
                  category=AlertCategory.PHISHING)
    is_dup, entry = dedup.check(alert)
    assert is_dup is False
    assert entry.count == 1


def test_same_alert_is_duplicate():
    dedup = AlertDeduplicator(window_seconds=300)
    alert1 = Alert(title="Phishing email", source="email_gateway",
                   category=AlertCategory.PHISHING)
    alert2 = Alert(title="Phishing email", source="email_gateway",
                   category=AlertCategory.PHISHING)
    dedup.check(alert1)
    is_dup, entry = dedup.check(alert2)
    assert is_dup is True
    assert entry.count == 2


def test_different_alerts_not_duplicate():
    dedup = AlertDeduplicator(window_seconds=300)
    alert1 = Alert(title="Phishing email", source="email_gateway",
                   category=AlertCategory.PHISHING)
    alert2 = Alert(title="Malware detected", source="edr",
                   category=AlertCategory.MALWARE)
    dedup.check(alert1)
    is_dup, _ = dedup.check(alert2)
    assert is_dup is False


def test_fingerprint_deterministic():
    dedup = AlertDeduplicator()
    alert = Alert(title="Test alert", source="siem",
                  category=AlertCategory.BRUTE_FORCE,
                  affected_user="user@company.com")
    fp1 = dedup.fingerprint(alert)
    fp2 = dedup.fingerprint(alert)
    assert fp1 == fp2
    assert len(fp1) == 16


def test_stats():
    dedup = AlertDeduplicator(window_seconds=300)
    alert = Alert(title="Repeated alert", source="siem",
                  category=AlertCategory.PHISHING)
    dedup.check(alert)
    dedup.check(Alert(title="Repeated alert", source="siem",
                      category=AlertCategory.PHISHING))
    dedup.check(Alert(title="Repeated alert", source="siem",
                      category=AlertCategory.PHISHING))
    stats = dedup.stats
    assert stats["total_alerts"] == 3
    assert stats["suppressed"] == 2
    assert stats["active_groups"] == 1


def test_severity_upgrade_on_dedup():
    dedup = AlertDeduplicator(window_seconds=300)
    alert1 = Alert(title="Alert", source="siem", category=AlertCategory.PHISHING,
                   severity=Severity.LOW)
    alert2 = Alert(title="Alert", source="siem", category=AlertCategory.PHISHING,
                   severity=Severity.HIGH)
    dedup.check(alert1)
    _, entry = dedup.check(alert2)
    assert entry.severity == Severity.HIGH
