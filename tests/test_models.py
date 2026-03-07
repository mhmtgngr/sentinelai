"""Tests for domain models."""

from src.core.models import (
    Alert,
    AlertCategory,
    AlertStatus,
    Decision,
    DecisionAction,
    Severity,
    SOARAction,
    TriageResult,
    UserEducation,
)


def test_alert_defaults():
    alert = Alert(title="Test alert")
    assert alert.id
    assert alert.status == AlertStatus.NEW
    assert alert.severity == Severity.MEDIUM
    assert alert.category == AlertCategory.SUSPICIOUS_ACTIVITY
    assert alert.timestamp is not None


def test_alert_full():
    alert = Alert(
        title="Phishing detected",
        severity=Severity.HIGH,
        category=AlertCategory.PHISHING,
        affected_user="user@company.com",
        affected_endpoint="WORKSTATION-01",
        affected_ip="10.0.0.50",
    )
    data = alert.model_dump(mode="json")
    restored = Alert(**data)
    assert restored.title == alert.title
    assert restored.affected_user == "user@company.com"


def test_decision_model():
    d = Decision(
        alert_id="abc",
        action=DecisionAction.ISOLATE_ENDPOINT,
        decided_by="analyst@company.com",
        reason="Confirmed malware",
    )
    assert d.action == DecisionAction.ISOLATE_ENDPOINT


def test_triage_result():
    tr = TriageResult(
        alert_id="abc",
        original_severity=Severity.MEDIUM,
        adjusted_severity=Severity.HIGH,
        category=AlertCategory.MALWARE,
        requires_human_decision=True,
    )
    assert tr.requires_human_decision is True


def test_soar_action():
    sa = SOARAction(
        alert_id="abc",
        action_type="isolate_endpoint",
        target="WORKSTATION-01",
    )
    assert sa.status == "pending"


def test_user_education():
    ue = UserEducation(
        alert_id="abc",
        user_email="user@company.com",
        category=AlertCategory.PHISHING,
        topics=["recognizing_phishing_emails"],
    )
    assert ue.sent_at is None
