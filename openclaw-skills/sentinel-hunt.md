# Sentinel-AI Hunt Skill

## Overview

Proactive threat hunting and IOC investigation. Queries across security data sources, correlates findings, enriches indicators, and maps to MITRE ATT&CK techniques.

## Trigger Patterns

- "hunt for threats related to"
- "investigate this IOC"
- "search for indicators of"
- "correlate events around"
- "check this IP/domain/hash"
- "look for lateral movement"

## API Integration

### Start Investigation

```
POST /api/v1/investigations
Content-Type: application/json

{
  "type": "hunt",
  "target": "203.0.113.50",
  "context": "Suspicious outbound connections detected by firewall",
  "priority": 1
}
```

### Query Adapter Data

```
GET /api/v1/adapters/health
```

### Check Related Threat Intel

```
GET /api/v1/memory/status
```

## Input Format

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | Investigation type: hunt, ioc_lookup, correlate |
| target | string | yes | IOC value, hostname, or hunt hypothesis |
| context | string | no | Additional context for the investigation |
| priority | int | no | 1 (critical) to 5 (low), default 2 |
| time_range | string | no | Lookback period (e.g., "24h", "7d") |
| sources | array | no | Specific adapters to query |

## Output Format

```json
{
  "investigation_id": "inv-uuid",
  "status": "completed",
  "findings": [
    {
      "source": "siem",
      "evidence_type": "network_connection",
      "data": {
        "src_ip": "10.0.1.42",
        "dst_ip": "203.0.113.50",
        "dst_port": 443,
        "bytes_out": 524288,
        "timestamp": "2024-01-15T03:42:00Z"
      },
      "relevance": 0.94
    }
  ],
  "ioc_enrichment": {
    "203.0.113.50": {
      "reputation": "malicious",
      "first_seen": "2024-01-10",
      "associated_malware": ["Cobalt Strike"],
      "threat_actors": ["APT29"]
    }
  },
  "attack_chain": [
    {"technique": "T1566.001", "phase": "initial_access", "evidence_count": 1},
    {"technique": "T1059.001", "phase": "execution", "evidence_count": 3},
    {"technique": "T1071.001", "phase": "command_and_control", "evidence_count": 7}
  ],
  "related_assets": [
    {"asset_id": "WS-042", "risk_score": 8.5, "relation": "communicates_with"}
  ],
  "recommendations": [
    "Isolate WS-042 — confirmed C2 communication",
    "Block 203.0.113.50 at perimeter firewall",
    "Search for T1059.001 artifacts on WS-042"
  ]
}
```

## Example Conversations

### IOC Investigation

**User:** Investigate IP 198.51.100.23 — it showed up in our firewall logs connecting to three internal hosts.

**Sentinel:** Investigation complete for **198.51.100.23**:

**Threat Intelligence:**
- **Reputation:** Malicious (confidence: 0.95)
- **Associated with:** Emotet botnet infrastructure
- **First seen:** 2024-01-08 in commercial threat feeds
- **ASN:** AS12345 (BulletProof Hosting Ltd.)

**Internal Activity (last 72h):**
| Timestamp | Source Host | Dest Port | Bytes |
|-----------|-----------|-----------|-------|
| Jan 15 03:42 | WS-042 | 443 | 512KB |
| Jan 15 04:15 | WS-087 | 8443 | 1.2MB |
| Jan 14 22:30 | SRV-DB-01 | 443 | 256KB |

**Attack Chain (MITRE ATT&CK):**
1. T1566.001 — Initial Access via phishing (probable, based on WS-042 email logs)
2. T1059.001 — PowerShell execution on WS-042
3. T1071.001 — HTTPS C2 to 198.51.100.23
4. T1021.002 — Lateral movement to WS-087 and SRV-DB-01

**Risk Assessment:** 3 assets compromised, database server involved — **CRITICAL**

### Proactive Hunt

**User:** Hunt for any signs of lateral movement in the engineering subnet 10.0.5.0/24 over the past week.

**Sentinel:** Proactive hunt results for **10.0.5.0/24** (last 7 days):

**Anomalies detected: 2**

1. **SMB scanning from 10.0.5.33** (Jan 14, 01:00-01:45)
   - 47 unique hosts contacted on port 445
   - Normal baseline: 3-5 SMB connections/day
   - MITRE: T1021.002 (SMB/Windows Admin Shares)

2. **Unusual RDP from 10.0.5.12 → 10.0.5.50** (Jan 13, 23:15)
   - First-time connection pair
   - Outside business hours
   - MITRE: T1021.001 (Remote Desktop Protocol)

No known IOCs matched, but behavioral patterns warrant investigation.

## Configuration

```yaml
hunt:
  default_lookback: "72h"
  max_lookback: "30d"
  parallel_adapter_queries: true
  enrichment_timeout_seconds: 30
  min_relevance_score: 0.5
  max_results_per_source: 100
```
