"""Tests for threat intelligence enrichment engine."""

from src.core.threat_intel import ThreatIntelEngine, ThreatIndicator
from src.core.models import Alert, AlertCategory, Severity


def test_enrich_no_indicators():
    engine = ThreatIntelEngine()
    alert = Alert(title="Test alert", affected_ip="10.0.0.1")
    result = engine.enrich(alert)
    assert result.has_matches is False
    assert result.risk_score > 0  # base severity score


def test_enrich_with_matching_ip():
    engine = ThreatIntelEngine()
    engine.add_indicator(ThreatIndicator(
        value="192.168.1.100",
        indicator_type="ip",
        threat_name="Known C2 Server",
        severity="critical",
    ))
    alert = Alert(title="Connection to suspicious IP",
                  affected_ip="192.168.1.100",
                  category=AlertCategory.SUSPICIOUS_ACTIVITY)
    result = engine.enrich(alert)
    assert result.has_matches is True
    assert len(result.matched_indicators) == 1
    assert result.matched_indicators[0].threat_name == "Known C2 Server"


def test_enrich_with_raw_data_match():
    engine = ThreatIntelEngine()
    engine.add_indicator(ThreatIndicator(
        value="evil.com",
        indicator_type="domain",
        threat_name="Phishing Domain",
    ))
    alert = Alert(
        title="Suspicious email",
        category=AlertCategory.PHISHING,
        raw_data={"domain": "evil.com"},
    )
    result = engine.enrich(alert)
    assert result.has_matches is True


def test_mitre_mapping():
    engine = ThreatIntelEngine()
    alert = Alert(title="Phishing", category=AlertCategory.PHISHING)
    result = engine.enrich(alert)
    assert "Initial Access" in result.mitre_tactics
    assert any("T1566" in t for t in result.mitre_techniques)


def test_risk_score_increases_with_indicators():
    engine = ThreatIntelEngine()
    engine.add_indicator(ThreatIndicator(
        value="10.0.0.1", indicator_type="ip", threat_name="Bad IP"))
    engine.add_indicator(ThreatIndicator(
        value="user@evil.com", indicator_type="email", threat_name="Bad Actor"))

    alert = Alert(title="Attack", affected_ip="10.0.0.1",
                  affected_user="user@evil.com",
                  severity=Severity.HIGH,
                  category=AlertCategory.LATERAL_MOVEMENT)
    result = engine.enrich(alert)
    assert result.risk_score > 0.6


def test_add_multiple_indicators():
    engine = ThreatIntelEngine()
    indicators = [
        ThreatIndicator(value="1.1.1.1", indicator_type="ip", threat_name="IP1"),
        ThreatIndicator(value="2.2.2.2", indicator_type="ip", threat_name="IP2"),
    ]
    engine.add_indicators(indicators)
    assert engine.indicator_count == 2


def test_severity_recommendation():
    engine = ThreatIntelEngine()
    engine.add_indicator(ThreatIndicator(
        value="10.0.0.1", indicator_type="ip", threat_name="Bad"))
    alert = Alert(title="Test", affected_ip="10.0.0.1",
                  severity=Severity.HIGH,
                  category=AlertCategory.RANSOMWARE)
    result = engine.enrich(alert)
    assert result.recommended_severity in (Severity.HIGH, Severity.CRITICAL)
