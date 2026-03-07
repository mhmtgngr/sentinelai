# Sentinel-AI Respond Skill

## Overview

Incident response and automated remediation. Selects and executes response playbooks, manages containment actions, and supports rollback of automated responses.

## Trigger Patterns

- "respond to this incident"
- "contain this threat"
- "block this IP"
- "isolate this host"
- "disable this account"
- "run the response playbook"
- "roll back the last action"

## API Integration

### List Pending Actions

```
GET /api/v1/incidents/{incident_id}
```

### Approve Action

```
POST /api/v1/incidents/{incident_id}/actions/{action_id}/approve
```

### Deny Action

```
POST /api/v1/incidents/{incident_id}/actions/{action_id}/deny
```

### Rollback Action

```
POST /api/v1/actions/{action_id}/rollback
```

### Check Action Status

```
GET /api/v1/actions/{action_id}
```

## Input Format

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| incident_id | string | yes | Target incident |
| action_type | string | no | Specific action: BLOCK_IP, ISOLATE_HOST, DISABLE_ACCOUNT, QUARANTINE_FILE, FORCE_PASSWORD_RESET |
| target | string | no | Specific target for the action |
| playbook | string | no | Named playbook to execute |
| auto_approve | bool | no | Skip approval for low-risk actions (default: false) |

## Output Format

```json
{
  "incident_id": "inc-uuid",
  "actions_taken": [
    {
      "action_id": "act-uuid-1",
      "type": "BLOCK_IP",
      "target": "203.0.113.50",
      "adapter": "firewall/paloalto",
      "status": "COMPLETED",
      "executed_at": "2024-01-15T04:00:00Z",
      "rollback_available": true
    },
    {
      "action_id": "act-uuid-2",
      "type": "ISOLATE_HOST",
      "target": "WS-042",
      "adapter": "edr/crowdstrike",
      "status": "PENDING_APPROVAL",
      "confidence": 0.82,
      "blast_radius": 1,
      "requires_approval": true
    }
  ],
  "playbook": "brute-force-response",
  "progress": "3/6 steps completed",
  "shadow_mode": false
}
```

## Action Types and Adapters

| Action | Adapter | Reversible | Approval Required |
|--------|---------|-----------|-------------------|
| BLOCK_IP | firewall/paloalto, waf/cloudflare | Yes | No (auto if confidence > 0.9) |
| UNBLOCK_IP | firewall/paloalto | Yes | No |
| ISOLATE_HOST | edr/crowdstrike | Yes | Yes (always) |
| QUARANTINE_FILE | edr/crowdstrike | Yes | Yes if on server |
| DISABLE_ACCOUNT | identity/entraid | Yes | Yes (always) |
| FORCE_PASSWORD_RESET | identity/entraid | No | Yes if privileged account |
| ADD_TO_WATCHLIST | waf/cloudflare | Yes | No |

## Example Conversations

### Automated Response

**User:** Respond to incident INC-2024-0156 — confirmed ransomware on WS-042.

**Sentinel:** Executing **ransomware-response** playbook for INC-2024-0156:

| Step | Action | Target | Status |
|------|--------|--------|--------|
| 1 | ISOLATE_HOST | WS-042 | **PENDING APPROVAL** |
| 2 | BLOCK_IP | 198.51.100.23 | Completed |
| 3 | BLOCK_IP | 198.51.100.24 | Completed |
| 4 | DISABLE_ACCOUNT | jsmith@corp.local | **PENDING APPROVAL** |
| 5 | ADD_TO_WATCHLIST | *.evil-domain.com | Completed |

**2 actions require your approval:**
- Isolate WS-042 (CrowdStrike) — will disconnect user from network
- Disable jsmith@corp.local (Entra ID) — user's primary account

Approve all, or review individually?

### Rollback

**User:** Roll back the IP block on 198.51.100.23 — it's a legitimate partner.

**Sentinel:** Rolling back action `act-2024-0847`:

- **Action:** UNBLOCK_IP 198.51.100.23
- **Adapter:** firewall/paloalto
- **Status:** Completed
- **Rolled back at:** 2024-01-15T06:30:00Z

The IP has been removed from the block list. I've also updated the threat intel cache to mark this IP as a known-good partner to prevent future false positives.

### Shadow Mode

**User:** What would you recommend for incident INC-2024-0160?

**Sentinel:** Running in **shadow mode** — recommendations only, no actions executed.

**Recommended response plan:**
1. Block source IP 10.200.5.99 at perimeter (confidence: 0.88)
2. Force password reset for svc-backup@corp.local (confidence: 0.91)
3. Scan all hosts in 10.0.3.0/24 for persistence mechanisms (confidence: 0.76)

Estimated blast radius: 2 (1 IP block + 1 account reset)
All actions are reversible.

Say "approve" to execute, or "approve 1,2" to execute selectively.

## Configuration

```yaml
response:
  shadow_mode: true
  confidence_threshold: 0.75
  max_blast_radius: 5
  require_approval:
    - ISOLATE_HOST
    - DISABLE_ACCOUNT
  auto_approve_above_confidence: 0.95
  playbook_directory: "config/playbooks/"
  rollback_window: "24h"
```
