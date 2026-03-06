"""Tests for ML detection engine components."""

import pytest
import numpy as np
from src.detection.anomaly_detector import AnomalyDetector
from src.detection.ueba import UEBAEngine
from src.detection.sigma_engine import SigmaEngine, SigmaRule


# --- Anomaly Detector ---

def test_anomaly_detector_train_and_detect():
    detector = AnomalyDetector(contamination=0.1)

    # Generate normal training data
    rng = np.random.RandomState(42)
    normal_data = rng.normal(loc=[100, 50, 10], scale=[10, 5, 2], size=(200, 3)).tolist()

    detector.train(normal_data, feature_names=["bytes_in", "bytes_out", "duration"])

    # Normal sample
    result = detector.detect([105, 48, 11])
    assert not result.is_anomaly
    assert result.anomaly_score < 0.5

    # Anomalous sample (far from training distribution)
    result = detector.detect([1000, 500, 100])
    assert result.is_anomaly
    assert result.anomaly_score > 0.3


def test_anomaly_detector_baselines():
    detector = AnomalyDetector()
    rng = np.random.RandomState(42)
    data = rng.normal(loc=[100], scale=[10], size=(100, 1)).tolist()
    detector.train(data, feature_names=["metric"])

    baselines = detector.get_baselines()
    assert "metric" in baselines
    assert abs(baselines["metric"]["mean"] - 100) < 5


def test_anomaly_detector_statistical_fallback():
    detector = AnomalyDetector()
    # Set baselines manually without training ML model
    detector._feature_names = ["metric1"]
    detector._baselines = {"metric1": {"mean": 100, "std": 10, "min": 70, "max": 130, "p95": 120, "p99": 125}}

    result = detector._statistical_detect([100])
    assert not result.is_anomaly

    result = detector._statistical_detect([200])  # 10 std devs away
    assert result.is_anomaly


def test_extract_network_features():
    event = {
        "bytes_in": 1500,
        "bytes_out": 300,
        "packets": 10,
        "duration": 5.0,
        "port": 443,
        "protocol": "tcp",
        "connection_count": 1,
        "failed_attempts": 0,
        "is_encrypted": True,
    }
    features = AnomalyDetector.extract_network_features(event)
    assert len(features) == 10
    assert features[0] == 1500.0
    assert features[5] == 1.0  # is_tcp


# --- UEBA Engine ---

def test_ueba_baseline_creation():
    engine = UEBAEngine()
    anomalies = engine.observe("user1", "user", {"login_count": 5, "bytes_transferred": 1000})
    assert len(anomalies) == 0  # First observation — no anomaly

    baseline = engine.get_entity_baseline("user1", "user")
    assert baseline is not None
    assert "login_count" in baseline["metrics"]


def test_ueba_anomaly_detection():
    engine = UEBAEngine()

    # Build baseline with 20 normal observations
    for i in range(20):
        engine.observe("user1", "user", {"login_count": 5 + (i % 3)})

    # Extreme anomaly
    anomalies = engine.observe("user1", "user", {"login_count": 500})
    assert len(anomalies) > 0
    assert anomalies[0].anomaly_type == "unusual_login_count"


def test_ueba_login_new_location():
    engine = UEBAEngine()

    # Establish baseline
    engine.observe("user1", "user", {"login_count": 1})
    engine._baselines["user:user1"].metrics["_known_ips"] = {
        "_values": ["10.0.0.1", "10.0.0.2"],
        "mean": 0, "std": 0, "count": 0, "last_updated": "",
    }

    # Login from new IP
    anomalies = engine.observe_login("user1", {"source_ip": "203.0.113.50", "hour": 14})
    new_location = [a for a in anomalies if a.anomaly_type == "new_login_location"]
    assert len(new_location) == 1


def test_ueba_stats():
    engine = UEBAEngine()
    engine.observe("user1", "user", {"metric1": 10})
    engine.observe("host1", "host", {"cpu": 50})

    stats = engine.get_stats()
    assert stats["entities_tracked"] == 2
    assert "user" in stats["entity_types"]
    assert "host" in stats["entity_types"]


# --- Sigma Engine ---

def test_sigma_rule_matching():
    engine = SigmaEngine()
    engine.add_rule(SigmaRule(
        rule_id="test-001",
        title="Test Rule",
        level="high",
        detection={
            "selection": {"event_type": "authentication_failure"},
            "condition": "selection",
        },
    ))

    matches = engine.evaluate({"event_type": "authentication_failure"})
    assert len(matches) == 1
    assert matches[0].rule.rule_id == "test-001"


def test_sigma_no_match():
    engine = SigmaEngine()
    engine.add_rule(SigmaRule(
        rule_id="test-002",
        title="Test Rule",
        detection={
            "selection": {"event_type": "malware_detected"},
            "condition": "selection",
        },
    ))

    matches = engine.evaluate({"event_type": "normal_login"})
    assert len(matches) == 0


def test_sigma_wildcard_matching():
    engine = SigmaEngine()
    engine.add_rule(SigmaRule(
        rule_id="test-003",
        title="Wildcard Test",
        detection={
            "selection": {"process_name": "powershell*"},
            "condition": "selection",
        },
    ))

    matches = engine.evaluate({"process_name": "powershell.exe"})
    assert len(matches) == 1


def test_sigma_contains_modifier():
    engine = SigmaEngine()
    engine.add_rule(SigmaRule(
        rule_id="test-004",
        title="Contains Test",
        detection={
            "selection": {"command_line|contains": "mimikatz"},
            "condition": "selection",
        },
    ))

    matches = engine.evaluate({"command_line": "C:\\tools\\mimikatz.exe privilege::debug"})
    assert len(matches) == 1


def test_sigma_and_condition():
    engine = SigmaEngine()
    engine.add_rule(SigmaRule(
        rule_id="test-005",
        title="AND condition",
        detection={
            "selection1": {"event_type": "process_creation"},
            "selection2": {"process_name": "cmd.exe"},
            "condition": "selection1 and selection2",
        },
    ))

    matches = engine.evaluate({"event_type": "process_creation", "process_name": "cmd.exe"})
    assert len(matches) == 1

    matches = engine.evaluate({"event_type": "process_creation", "process_name": "notepad.exe"})
    assert len(matches) == 0


def test_sigma_load_rules_from_dir():
    engine = SigmaEngine()
    count = engine.load_rules("config/sigma-rules")
    assert count >= 4  # We created 4 sigma rule files

    stats = engine.get_stats()
    assert stats["total_rules"] >= 4
