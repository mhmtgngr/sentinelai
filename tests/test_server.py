"""Tests for FastAPI server endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.server import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_ready_endpoint(client):
    resp = client.get("/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert "components" in data


def test_metrics_endpoint(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "event_bus_queue_depth" in data
    assert "websocket_connections" in data


def test_list_alerts(client):
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert "alerts" in data
    assert "total" in data


def test_list_incidents(client):
    resp = client.get("/api/v1/incidents")
    assert resp.status_code == 200
    data = resp.json()
    assert "incidents" in data


def test_get_alert_not_found(client):
    resp = client.get("/api/v1/alerts/nonexistent")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("detail") == "not_found" or data.get("alert_id") == "nonexistent"


def test_get_incident_not_found(client):
    resp = client.get("/api/v1/incidents/nonexistent")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("detail") == "not_found"


def test_adapter_health(client):
    resp = client.get("/api/v1/adapters/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "adapters" in data


def test_memory_status(client):
    resp = client.get("/api/v1/memory/status")
    assert resp.status_code == 200


def test_dlq_list(client):
    resp = client.get("/api/v1/dlq")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data


def test_submit_verdict(client):
    resp = client.post("/api/v1/alerts/test-alert/verdict?verdict=TRUE_POSITIVE&notes=test")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "verdict_recorded"


def test_create_investigation(client):
    resp = client.post("/api/v1/investigations?type=hunt&target=10.0.0.1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "queued"


def test_approve_action(client):
    resp = client.post("/api/v1/incidents/inc-1/actions/act-1/approve")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "approved"


def test_deny_action(client):
    resp = client.post("/api/v1/incidents/inc-1/actions/act-1/deny")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "denied"


def test_get_action(client):
    resp = client.get("/api/v1/actions/act-1")
    assert resp.status_code == 200


def test_rollback_action(client):
    resp = client.post("/api/v1/actions/act-1/rollback")
    assert resp.status_code == 200
