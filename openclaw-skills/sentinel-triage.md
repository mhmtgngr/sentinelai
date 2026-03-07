# Sentinel-AI Triage Skill

## Overview

Automated alert triage and classification for security operations. Analyzes incoming alerts, checks for duplicates, enriches with threat intelligence, and assigns severity/priority ratings.

## Trigger Patterns

- "triage this alert"
- "classify this security event"
- "check if this is a false positive"
- "what's the severity of this alert"
- "is this alert a duplicate"
- "analyze this detection"

## API Integration

### Submit Alert for Triage

```
POST /api/v1/alerts
Content-Type: application/json

{
  "source": "siem",
  "title": "Multiple failed SSH logins from 203.0.113.50",
  "raw_event": {
    "src_ip": "203.0.113.50",
    "dest_ip": "10.0.1.25",
    "event_type": "authentication_failure",
    "count": 47,
    "time_window": "5m"
  }
}
```

### Check Triage Result

```
GET /api/v1/alerts/{alert_id}
```

### Submit Analyst Verdict (Feedback Loop)

```
POST /api/v1/alerts/{alert_id}/verdict
Content-Type: application/json

{
  "verdict": "TRUE_POSITIVE",
  "notes": "Confirmed brute force from known malicious IP"
}
```

## Input Format

The skill accepts security alerts with the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| source | string | yes | Alert source (siem, edr, firewall, etc.) |
| title | string | yes | Alert summary |
| raw_event | object | yes | Original event data |
| severity | string | no | Pre-assigned severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) |
| iocs | array | no | Known indicators of compromise |

## Output Format

```json
{
  "alert_id": "alert-uuid",
  "verdict": "TRUE_POSITIVE",
  "confidence": 0.87,
  "severity": "HIGH",
  "priority": 2,
  "reasoning": "47 failed SSH attempts from single IP in 5 minutes matches brute-force pattern. IP found in threat intel feeds.",
  "mitre_techniques": ["T1110.001"],
  "recommended_actions": [
    {"type": "BLOCK_IP", "target": "203.0.113.50"},
    {"type": "FORCE_PASSWORD_RESET", "target": "admin@server-25"}
  ],
  "similar_past_alerts": [
    {"alert_id": "prev-alert-1", "similarity": 0.92, "verdict": "TRUE_POSITIVE"}
  ]
}
```

## Example Conversations

### Basic Triage

**User:** Triage this alert — we're seeing 200+ DNS queries to a single domain from workstation WS-042 in the last 10 minutes.

**Sentinel:** I've analyzed the alert. Here's my assessment:

- **Verdict:** TRUE_POSITIVE (confidence: 0.91)
- **Severity:** HIGH
- **Classification:** Possible DNS tunneling / C2 communication
- **MITRE ATT&CK:** T1071.004 (Application Layer Protocol: DNS)

**Key findings:**
1. Query volume (200+ in 10min) far exceeds baseline for this workstation (avg 15/10min)
2. Target domain `x7k2m.example.net` uses high-entropy subdomain labels consistent with DNS tunneling
3. Similar pattern seen in 2 previous confirmed incidents

**Recommended actions:**
1. Isolate WS-042 from network
2. Block domain at DNS resolver
3. Investigate WS-042 for malware

### Duplicate Detection

**User:** Check if this is a duplicate — failed login attempt from 10.0.5.33 to DC-01.

**Sentinel:** This alert is a **duplicate** of existing alert `ALT-2024-0847` (similarity: 0.96).

The existing alert already tracks 12 failed login attempts from 10.0.5.33 to DC-01 over the past 30 minutes. I've merged this event into the existing alert's timeline rather than creating a new one.

Current status of ALT-2024-0847: Under investigation by Threat Hunter agent.

## Configuration

```yaml
triage:
  confidence_threshold: 0.75
  dedup_similarity_threshold: 0.85
  dedup_time_window: "1h"
  max_similar_alerts: 5
  auto_escalate_severity: ["CRITICAL"]
  fallback_to_rules: true
```
