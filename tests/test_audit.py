"""Tests for the audit trail."""

from src.core.audit import AuditTrail


def test_log_entry():
    audit = AuditTrail()
    entry = audit.log(event_type="test.event", alert_id="abc", action="test")
    assert entry.event_type == "test.event"
    assert entry.alert_id == "abc"
    assert audit.total_entries == 1


def test_log_alert_ingested():
    audit = AuditTrail()
    entry = audit.log_alert_ingested("id-1", "Phishing detected", "email_gateway")
    assert entry.event_type == "alert.ingested"
    assert "Phishing detected" in entry.detail


def test_log_triage():
    audit = AuditTrail()
    entry = audit.log_triage("id-1", "phishing", "high", autonomous=True)
    assert entry.event_type == "alert.triaged"
    assert "autonomous=True" in entry.detail


def test_log_decision():
    audit = AuditTrail()
    entry = audit.log_decision("id-1", "isolate_endpoint", "analyst@co.com", "Confirmed threat")
    assert entry.actor == "analyst@co.com"
    assert entry.action == "isolate_endpoint"


def test_log_soar_action():
    audit = AuditTrail()
    entry = audit.log_soar_action("id-1", "block_ip", "10.0.0.1", "completed", "IP blocked")
    assert entry.event_type == "soar.executed"
    assert "10.0.0.1" in entry.detail


def test_log_dedup_suppressed():
    audit = AuditTrail()
    entry = audit.log_dedup_suppressed("id-1", "abc123", 5)
    assert entry.event_type == "alert.deduplicated"
    assert "5" in entry.detail


def test_filter_by_alert_id():
    audit = AuditTrail()
    audit.log(event_type="e1", alert_id="a1")
    audit.log(event_type="e2", alert_id="a2")
    audit.log(event_type="e3", alert_id="a1")
    entries = audit.get_entries(alert_id="a1")
    assert len(entries) == 2
    assert all(e.alert_id == "a1" for e in entries)


def test_filter_by_event_type():
    audit = AuditTrail()
    audit.log(event_type="alert.ingested", alert_id="a1")
    audit.log(event_type="decision.made", alert_id="a1")
    audit.log(event_type="alert.ingested", alert_id="a2")
    entries = audit.get_entries(event_type="alert.ingested")
    assert len(entries) == 2


def test_get_entries_limit():
    audit = AuditTrail()
    for i in range(10):
        audit.log(event_type="test", alert_id=str(i))
    entries = audit.get_entries(limit=3)
    assert len(entries) == 3
