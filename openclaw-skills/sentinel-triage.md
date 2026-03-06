# Sentinel-AI: Alert Triage Skill

## Description
Autonomous alert triage and prioritization for security operations. Analyzes incoming alerts, deduplicates, classifies by attack type, maps to MITRE ATT&CK, and routes based on severity.

## Trigger
- New security alert received from any connected adapter
- Manual alert submission via API
- Webhook from SIEM/SOAR platforms

## Actions
1. **Deduplicate** — Check if alert matches existing known alert pattern
2. **Classify** — Determine attack type (brute force, SQLi, XSS, lateral movement, etc.)
3. **Score** — Calculate severity score (0-100) based on multiple factors
4. **Enrich** — Map to MITRE ATT&CK tactics and techniques
5. **Route** — Escalate high-severity alerts, auto-close known false positives

## Parameters
- `alert_data`: The raw alert payload
- `auto_escalate`: Whether to auto-escalate high severity (default: true)
- `dedup_window`: Time window for deduplication in minutes (default: 60)

## Output
- Triaged alert with severity score, attack classification, and MITRE mapping
- Routing decision (escalated / triaged / false_positive)
