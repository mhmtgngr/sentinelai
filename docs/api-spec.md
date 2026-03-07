# API Specification

> FastAPI endpoint specifications for Sentinel-AI.
> See [README.md](../README.md) for architectural overview.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

All endpoints (except `/health`, `/ready`, `/metrics`) require authentication:

- **OAuth2/OIDC Bearer Token**: `Authorization: Bearer <token>`
- **API Key**: `X-API-Key: <key>` (for programmatic access)

## RBAC Roles

| Role | Permissions |
|------|-------------|
| `viewer` | Read alerts, incidents, adapter status, dashboards |
| `operator` | All viewer permissions + trigger investigations, approve actions, manage DLQ |
| `admin` | All operator permissions + configure adapters, manage agents, system settings |

## Rate Limiting

| Endpoint Category | Rate Limit |
|-------------------|-----------|
| Read endpoints | 100 requests/minute |
| Write/action endpoints | 20 requests/minute |
| WebSocket connections | 10 concurrent per user |

---

## Health & Monitoring

### `GET /health`
Liveness check. No auth required.

**Response** `200 OK`:
```json
{
  "status": "healthy",
  "uptime_seconds": 86400,
  "version": "0.1.0"
}
```

### `GET /ready`
Readiness check — verifies all critical dependencies. No auth required.

**Response** `200 OK`:
```json
{
  "status": "ready",
  "components": {
    "event_bus": "healthy",
    "postgresql": "healthy",
    "chromadb": "healthy",
    "adapters": {
      "wazuh": "healthy",
      "paloalto": "degraded",
      "crowdstrike": "healthy"
    }
  }
}
```

**Response** `503 Service Unavailable`: If any critical component is down.

### `GET /metrics`
Prometheus metrics endpoint. No auth required.

---

## Alerts

### `GET /api/v1/alerts`
List alerts with filtering and pagination.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | all | Filter by status: `open`, `triaged`, `investigating`, `resolved` |
| `severity` | string | all | Filter by severity: `critical`, `high`, `medium`, `low` |
| `since` | ISO8601 | 24h ago | Start time |
| `limit` | int | 50 | Max results (1-200) |
| `offset` | int | 0 | Pagination offset |

**Response** `200 OK`:
```json
{
  "alerts": [
    {
      "id": "ALT-2024-0042",
      "severity": "HIGH",
      "triage_verdict": "TRUE_POSITIVE",
      "confidence_score": 0.87,
      "event_count": 3,
      "mitre_tactic": "Initial Access",
      "assigned_agent": "threat_hunter",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 142,
  "limit": 50,
  "offset": 0
}
```

### `GET /api/v1/alerts/{alert_id}`
Get detailed alert with all events.

### `POST /api/v1/alerts/{alert_id}/verdict`
Submit analyst verdict (operator+ role).

**Request Body:**
```json
{
  "verdict": "TRUE_POSITIVE",
  "notes": "Confirmed brute force from known bad IP"
}
```

---

## Incidents

### `GET /api/v1/incidents`
List incidents with filtering.

### `GET /api/v1/incidents/{incident_id}`
Get detailed incident with timeline, actions, and affected assets.

### `POST /api/v1/incidents/{incident_id}/actions/{action_id}/approve`
Approve a pending action (operator+ role).

### `POST /api/v1/incidents/{incident_id}/actions/{action_id}/deny`
Deny a pending action (operator+ role).

---

## Investigations

### `POST /api/v1/investigations`
Trigger a manual investigation (operator+ role). This is the endpoint OpenClaw skills call.

**Request Body:**
```json
{
  "type": "hunt",
  "target": "10.0.0.5",
  "context": "Suspicious outbound traffic reported by NOC",
  "priority": 1
}
```

**Response** `202 Accepted`:
```json
{
  "investigation_id": "INV-2024-0015",
  "status": "queued",
  "estimated_completion": "2024-01-15T10:35:00Z"
}
```

---

## Actions

### `GET /api/v1/actions/{action_id}`
Get action details including rollback status.

### `POST /api/v1/actions/{action_id}/rollback`
Rollback a previously executed action (operator+ role).

**Response** `200 OK`:
```json
{
  "action_id": "ACT-2024-0099",
  "status": "ROLLED_BACK",
  "rollback_executed_at": "2024-01-15T11:00:00Z"
}
```

---

## Adapters

### `GET /api/v1/adapters/health`
Get health status of all registered adapters.

### `GET /api/v1/adapters/{adapter_id}/health`
Get detailed health for a specific adapter.

---

## Dead Letter Queue

### `GET /api/v1/dlq`
List DLQ entries.

### `POST /api/v1/dlq/{event_id}/replay`
Replay a single DLQ event.

### `POST /api/v1/dlq/replay-all`
Replay all DLQ events (admin role).

### `DELETE /api/v1/dlq?older_than={duration}`
Purge old DLQ events (admin role).

---

## WebSocket

### `WS /api/v1/ws/events`
Real-time event stream. Requires authentication via query parameter: `?token=<bearer_token>`.

**Event Types:**

```json
{"type": "alert.new", "data": {"alert_id": "ALT-...", "severity": "HIGH"}}
{"type": "alert.triaged", "data": {"alert_id": "ALT-...", "verdict": "TRUE_POSITIVE"}}
{"type": "incident.created", "data": {"incident_id": "INC-...", "alert_count": 3}}
{"type": "action.executed", "data": {"action_id": "ACT-...", "type": "BLOCK_IP", "status": "SUCCESS"}}
{"type": "action.pending_approval", "data": {"action_id": "ACT-...", "type": "ISOLATE_HOST"}}
{"type": "adapter.health", "data": {"adapter": "paloalto", "status": "degraded"}}
```

**Filtering:**
Send a filter message after connecting:
```json
{"subscribe": ["alert.new", "action.pending_approval"]}
```
