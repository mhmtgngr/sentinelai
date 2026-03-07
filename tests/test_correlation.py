"""Tests for alert correlation engine."""

from src.core.correlation import CorrelationEngine
from src.core.models import Alert, AlertCategory, Severity


def test_first_alert_creates_cluster():
    engine = CorrelationEngine()
    alert = Alert(title="Phishing", category=AlertCategory.PHISHING,
                  affected_user="user@company.com")
    result = engine.correlate(alert)
    # First alert creates a new cluster, returns None
    assert result is None
    assert engine.stats["total_clusters"] == 1


def test_related_alerts_correlate():
    engine = CorrelationEngine()
    alert1 = Alert(title="Phishing email", category=AlertCategory.PHISHING,
                   affected_user="user@company.com")
    alert2 = Alert(title="Credential compromise",
                   category=AlertCategory.CREDENTIAL_COMPROMISE,
                   affected_user="user@company.com")
    engine.correlate(alert1)
    cluster = engine.correlate(alert2)
    assert cluster is not None
    assert cluster.alert_count == 2
    assert cluster.is_multi_stage is True


def test_unrelated_alerts_separate_clusters():
    engine = CorrelationEngine()
    alert1 = Alert(title="Alert A", category=AlertCategory.PHISHING,
                   affected_user="alice@company.com")
    alert2 = Alert(title="Alert B", category=AlertCategory.BRUTE_FORCE,
                   affected_user="bob@company.com",
                   affected_ip="10.0.0.2")
    engine.correlate(alert1)
    result = engine.correlate(alert2)
    assert result is None
    assert engine.stats["total_clusters"] == 2


def test_kill_chain_detection():
    engine = CorrelationEngine()
    # Simulate a multi-stage attack
    alerts = [
        Alert(title="Phishing email", category=AlertCategory.PHISHING,
              affected_user="victim@company.com"),
        Alert(title="Credential stolen", category=AlertCategory.CREDENTIAL_COMPROMISE,
              affected_user="victim@company.com"),
        Alert(title="Lateral movement", category=AlertCategory.LATERAL_MOVEMENT,
              affected_user="victim@company.com",
              affected_endpoint="SERVER-01"),
    ]
    engine.correlate(alerts[0])
    engine.correlate(alerts[1])
    cluster = engine.correlate(alerts[2])
    assert cluster is not None
    assert cluster.alert_count == 3
    assert cluster.is_multi_stage is True
    assert len(cluster.categories) == 3


def test_shared_endpoint_correlation():
    engine = CorrelationEngine()
    alert1 = Alert(title="Malware on WS-01", category=AlertCategory.MALWARE,
                   affected_endpoint="WS-01")
    alert2 = Alert(title="Ransomware on WS-01", category=AlertCategory.RANSOMWARE,
                   affected_endpoint="WS-01")
    engine.correlate(alert1)
    cluster = engine.correlate(alert2)
    assert cluster is not None
    assert cluster.is_multi_stage is True


def test_max_severity_tracked():
    engine = CorrelationEngine()
    alert1 = Alert(title="Low alert", severity=Severity.LOW,
                   category=AlertCategory.POLICY_VIOLATION,
                   affected_user="user@co.com")
    alert2 = Alert(title="Critical alert", severity=Severity.CRITICAL,
                   category=AlertCategory.RANSOMWARE,
                   affected_user="user@co.com")
    engine.correlate(alert1)
    cluster = engine.correlate(alert2)
    assert cluster is not None
    assert cluster.max_severity == Severity.CRITICAL


def test_get_multi_stage_clusters():
    engine = CorrelationEngine()
    alert1 = Alert(title="A", category=AlertCategory.PHISHING,
                   affected_user="u@co.com")
    alert2 = Alert(title="B", category=AlertCategory.CREDENTIAL_COMPROMISE,
                   affected_user="u@co.com")
    engine.correlate(alert1)
    engine.correlate(alert2)
    multi = engine.get_multi_stage_clusters()
    assert len(multi) == 1
