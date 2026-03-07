# Security Model

> Threat model, approval policies, and security controls for Sentinel-AI.
> See [README.md](../README.md) for architectural overview.

## Threat Model

Sentinel-AI is a security platform that controls critical infrastructure. It is itself a high-value target.

### Attack Surface

| Surface | Threat | Impact |
|---------|--------|--------|
| **Log ingestion** | Prompt injection in log fields (user-agent, hostname, command) | LLM makes incorrect decisions, misclassifies attacks |
| **Adapter credentials** | Credential theft from config/memory/env | Attacker gains admin access to firewalls, SIEM, EDR |
| **API endpoints** | Unauthorized access, SSRF, injection | Attacker triggers actions, reads sensitive data |
| **LLM provider** | Compromised LLM returns malicious outputs | Platform takes incorrect/destructive actions |
| **Vector store** | Data poisoning via manipulated feedback | Future triage accuracy degrades over time |
| **OpenClaw channel** | Impersonation of analyst commands | Unauthorized investigations or actions triggered |
| **Supply chain** | Compromised dependencies | Full platform compromise |
| **Internal network** | Lateral movement to/from Sentinel-AI containers | Platform used as pivot point in attack |

### Trust Boundaries

```
UNTRUSTED:
  - All data from security products (logs, alerts, telemetry)
  - LLM outputs (reasoning, recommendations, classifications)
  - External threat intelligence feeds
  - User input via OpenClaw channels

SEMI-TRUSTED:
  - Analyst verdicts (validated but could be social-engineered)
  - Internal event bus messages (authenticated but could be replayed)

TRUSTED:
  - Action validation policy rules (deterministic, code-reviewed)
  - Configuration files (reviewed, versioned, access-controlled)
  - Adapter interface contracts (type-checked, tested)
```

## Approval Policy Matrix

Every action goes through the action validation layer. The approval requirement depends on:

| Action Type | Confidence >= 0.85 | Confidence 0.75-0.84 | Confidence < 0.75 |
|-------------|--------------------|-----------------------|--------------------|
| **Read-only** (query logs, enrich) | Auto | Auto | Auto |
| **Low-risk** (add to watchlist, create alert) | Auto | Auto | Human approval |
| **Medium-risk** (block external IP, disable user) | Auto | Human approval | Human approval |
| **High-risk** (isolate host, revoke admin creds) | Human approval | Human approval | Multi-party approval |
| **Critical** (block subnet, disable OU, modify firewall policy) | Multi-party approval | Multi-party approval | Denied — manual only |

### Blast Radius Override

Regardless of confidence, if an action affects more than N assets (default: 5), it requires human approval. This prevents a single misclassification from causing widespread disruption.

### Shadow Mode

New deployments start in shadow mode:
- All pipelines run normally
- Agent decisions are logged but **not executed**
- Recommended actions are sent to analysts for review
- After validation period (configurable, default: 2 weeks), operators can enable autonomous execution per action type

## Prompt Injection Defense

### Input Sanitization Pipeline

All external data passes through sanitization before inclusion in LLM prompts:

```
Raw log data from adapter
  -> Strip control characters (Unicode categories Cc, Cf)
  -> Detect and escape known injection patterns:
     - "Ignore previous instructions"
     - "You are now..."
     - "System prompt:"
     - Role-switching markers ("### Human:", "### Assistant:")
  -> Truncate oversized fields (max 2048 chars per field)
  -> Wrap in structured data delimiters:
     <security_event_data>
       {sanitized JSON}
     </security_event_data>
  -> Include in prompt AFTER system instructions (never before)
```

### Structured Output Enforcement

Agents do not produce freeform text that gets interpreted as actions. Instead:

1. LLM generates a structured `AgentDecision` JSON object
2. JSON is parsed with Pydantic strict validation
3. `action_type` must be a member of the `ActionType` enum — unknown types are rejected
4. `target` must match a known asset in the asset inventory — unknown targets are flagged
5. `confidence` must be a float 0.0-1.0 — values outside range are clamped and logged

### Action Validation Allowlist

The action validation layer uses a **deterministic policy engine** (not LLM-based):

```python
ACTION_ALLOWLIST = {
    ActionType.BLOCK_IP: {
        "requires_corroboration": True,
        "max_targets_per_action": 10,
        "excluded_ranges": ["10.0.0.0/8"],  # Internal ranges require approval
        "min_confidence": 0.75,
    },
    ActionType.DISABLE_ACCOUNT: {
        "requires_corroboration": True,
        "max_targets_per_action": 1,
        "excluded_accounts": ["admin", "service-*"],  # Service accounts need approval
        "min_confidence": 0.85,
    },
    ActionType.ISOLATE_HOST: {
        "requires_corroboration": True,
        "max_targets_per_action": 1,
        "always_requires_human": True,  # Never auto-approved
        "min_confidence": 0.90,
    },
}
```

## Credential Management

### Storage

| Environment | Method |
|-------------|--------|
| Local dev | `.env` file (gitignored) |
| CI/CD | GitHub Actions secrets / environment variables |
| Production | HashiCorp Vault / AWS Secrets Manager / Azure Key Vault |

### Credential Scoping

Each adapter receives minimum-privilege credentials:

| Adapter | Required Permissions | Never Granted |
|---------|---------------------|---------------|
| Firewall | Read rules, add/remove block rules | Modify policies, admin access |
| SIEM | Read logs, create alerts | Delete logs, modify retention |
| EDR | Read telemetry, isolate endpoint | Uninstall agent, modify policies |
| Identity | Read users, disable accounts | Delete accounts, modify roles |

### Rotation Schedule

| Credential Type | Rotation Interval | Method |
|----------------|-------------------|--------|
| API keys | 90 days | Automated via secrets manager |
| OAuth client secrets | 180 days | Automated via secrets manager |
| Database passwords | 90 days | Automated via secrets manager |
| TLS certificates | 365 days (or shorter per policy) | Automated via cert-manager |

### Rotation Procedure

1. Secrets manager generates new credential
2. New credential is validated against the target system
3. Adapter configuration is hot-reloaded with new credential
4. Old credential is revoked after grace period (default: 1 hour)
5. Rotation event is logged in audit trail

## Incident Response for Platform Compromise

If Sentinel-AI itself is compromised:

### Indicators of Compromise

- Unexpected actions executed (not matching any alert investigation)
- Adapter credentials accessed from unexpected source
- LLM token usage spike without corresponding alert volume
- Audit log gaps or hash chain breaks
- Unusual network traffic from Sentinel-AI containers

### Response Procedure

1. **Isolate**: Disconnect Sentinel-AI from all adapters (kill adapter network access)
2. **Preserve**: Snapshot all container volumes, export audit logs, capture network flows
3. **Assess**: Review audit trail for unauthorized actions; check if any automated actions were attacker-initiated
4. **Rollback**: Undo any unauthorized actions using `ActionResult.rollback_procedure`
5. **Rotate**: All adapter credentials, API keys, database passwords, TLS certificates
6. **Rebuild**: Redeploy from known-good container images (verified by hash)
7. **Review**: Post-incident analysis of how the compromise occurred; update security controls
