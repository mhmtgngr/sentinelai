"""Tests for the autonomous triage agent."""

import pytest
from src.core.models import Alert, AlertCategory, Severity
from src.agents.triage_agent import TriageAgent


@pytest.fixture
def agent():
    return TriageAgent()


def test_classify_phishing(agent):
    alert = Alert(title="Suspicious phishing email detected", source="email_gateway")
    assert agent.classify(alert) == AlertCategory.PHISHING


def test_classify_malware(agent):
    alert = Alert(title="Malware payload detected on endpoint", source="edr")
    assert agent.classify(alert) == AlertCategory.MALWARE


def test_classify_brute_force(agent):
    alert = Alert(
        title="Multiple failed login attempts",
        description="Brute force attack detected from 10.0.0.1",
    )
    assert agent.classify(alert) == AlertCategory.BRUTE_FORCE


def test_classify_ransomware(agent):
    alert = Alert(title="Ransomware encryption activity detected", source="edr")
    assert agent.classify(alert) == AlertCategory.RANSOMWARE


def test_classify_unknown_falls_back(agent):
    alert = Alert(title="Something unusual happened")
    result = agent.classify(alert)
    assert result == AlertCategory.SUSPICIOUS_ACTIVITY


def test_severity_escalation_ransomware(agent):
    alert = Alert(title="Ransomware", severity=Severity.MEDIUM)
    result = agent.adjust_severity(alert, AlertCategory.RANSOMWARE)
    assert result == Severity.CRITICAL


def test_severity_no_escalation_low_category(agent):
    alert = Alert(title="Policy issue", severity=Severity.LOW)
    result = agent.adjust_severity(alert, AlertCategory.POLICY_VIOLATION)
    assert result == Severity.LOW


def test_full_triage_phishing_with_user(agent):
    alert = Alert(
        title="Phishing email with credential harvesting link",
        source="email_gateway",
        severity=Severity.MEDIUM,
        affected_user="john.doe@company.com",
    )
    result = agent.triage(alert)
    assert result.category == AlertCategory.PHISHING
    assert result.education_needed is True
    assert "recognizing_phishing_emails" in result.education_topics
    assert "block_sender" in result.recommended_actions


def test_full_triage_critical_requires_human(agent):
    alert = Alert(
        title="Ransomware encryption detected",
        severity=Severity.HIGH,
        source="edr",
    )
    result = agent.triage(alert)
    assert result.adjusted_severity == Severity.CRITICAL
    assert result.requires_human_decision is True
