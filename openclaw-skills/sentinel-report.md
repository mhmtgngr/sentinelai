# Sentinel-AI Report Skill

## Overview

Generate forensic reports, compliance assessments, and incident summaries. Builds detailed timelines, documents evidence chains, and produces audit-ready reports.

## Trigger Patterns

- "generate a report for"
- "summarize this incident"
- "build a timeline"
- "run a compliance check"
- "create a forensic report"
- "audit this system"

## API Integration

### Get Incident Timeline

```
GET /api/v1/incidents/{incident_id}
```

### Get Alert Details

```
GET /api/v1/alerts/{alert_id}
```

### Get Memory/Pattern Data

```
GET /api/v1/memory/status
```

### Adapter Health (for scope)

```
GET /api/v1/adapters/health
```

## Input Format

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | Report type: forensic, compliance, summary, timeline |
| target | string | yes | Incident ID, asset ID, or scope description |
| framework | string | no | Compliance framework: GDPR, HIPAA, PCI-DSS, SOC2, NIST |
| time_range | string | no | Report period (e.g., "24h", "7d", "30d") |
| format | string | no | Output format: json, markdown (default: markdown) |

## Output Format

### Forensic Report

```json
{
  "report_id": "rpt-uuid",
  "type": "forensic",
  "incident_id": "inc-uuid",
  "generated_at": "2024-01-15T08:00:00Z",
  "executive_summary": "Confirmed credential stuffing attack targeting 3 user accounts...",
  "timeline": [
    {
      "timestamp": "2024-01-14T22:30:00Z",
      "event": "First failed authentication from 203.0.113.50",
      "source": "siem/wazuh",
      "significance": "Initial attack activity"
    }
  ],
  "evidence": [
    {
      "evidence_id": "ev-001",
      "type": "network_log",
      "source": "firewall/paloalto",
      "description": "47 connection attempts from 203.0.113.50"
    }
  ],
  "root_cause": "Compromised credentials from third-party breach reused against corporate SSO",
  "impact_assessment": {
    "affected_assets": 3,
    "data_exposure": "none_confirmed",
    "business_impact": "low"
  },
  "mitre_mapping": [
    {"technique": "T1110.004", "name": "Credential Stuffing", "phase": "credential_access"}
  ],
  "recommendations": [
    "Enforce MFA for all user accounts",
    "Implement credential breach monitoring",
    "Rate-limit authentication endpoints"
  ]
}
```

### Compliance Assessment

```json
{
  "report_id": "rpt-uuid",
  "type": "compliance",
  "framework": "PCI-DSS",
  "scope": "payment processing environment",
  "assessment_date": "2024-01-15",
  "findings": [
    {
      "requirement": "6.1",
      "title": "Establish a process to identify security vulnerabilities",
      "status": "partially_compliant",
      "details": "Vulnerability scanning is active but scan frequency does not meet 90-day requirement",
      "remediation": "Increase automated scan frequency to weekly"
    }
  ],
  "summary": {
    "total_requirements": 12,
    "compliant": 9,
    "partially_compliant": 2,
    "non_compliant": 1
  }
}
```

## Example Conversations

### Forensic Report

**User:** Generate a forensic report for incident INC-2024-0156.

**Sentinel:**

# Forensic Report — INC-2024-0156

**Generated:** 2024-01-15 08:00 UTC | **Classification:** CONFIDENTIAL

## Executive Summary

On January 14, 2024 at 22:30 UTC, a credential stuffing attack was detected targeting the corporate SSO portal. The attacker used compromised credentials from a known third-party breach to successfully authenticate as 1 of 3 targeted accounts. The compromised session lasted 47 minutes before automated detection and containment.

## Timeline

| Time (UTC) | Event | Source |
|------------|-------|--------|
| Jan 14 22:30 | First failed auth from 203.0.113.50 | SIEM |
| Jan 14 22:31-23:10 | 46 additional failed attempts (3 accounts) | SIEM |
| Jan 14 23:08 | Successful auth as jsmith@corp.local | SIEM |
| Jan 14 23:12 | Anomalous file access on SharePoint | EDR |
| Jan 14 23:55 | Alert triggered: brute force detection | Sentinel-AI |
| Jan 14 23:56 | Automated IP block (203.0.113.50) | Firewall |
| Jan 15 00:02 | Account jsmith disabled | Identity |
| Jan 15 00:15 | Session terminated | Identity |

## Evidence Chain

1. **EV-001:** Firewall logs showing 47 connections from 203.0.113.50
2. **EV-002:** Authentication logs — 46 failures, 1 success
3. **EV-003:** SharePoint audit logs — 12 file accesses during compromised session
4. **EV-004:** EDR telemetry — no malware or persistence mechanisms detected

## Root Cause

Credentials for jsmith@corp.local were exposed in the ExampleCorp breach (Dec 2023). Password reuse allowed successful authentication. MFA was not enforced for this account.

## Impact

- **Affected assets:** 1 user account, SharePoint site
- **Data exposure:** 12 files accessed, none confirmed exfiltrated
- **Business impact:** Low (no sensitive data in accessed files)

## MITRE ATT&CK Mapping

- T1110.004 — Credential Stuffing
- T1078.004 — Valid Accounts: Cloud Accounts

## Recommendations

1. Enforce MFA for all accounts (Priority: Critical)
2. Implement credential breach monitoring service
3. Review and restrict SharePoint permissions
4. Rate-limit authentication to 5 attempts/minute

### Compliance Check

**User:** Run a compliance check against PCI-DSS for the payment environment.

**Sentinel:**

# PCI-DSS Compliance Assessment — Payment Environment

**Date:** 2024-01-15 | **Framework:** PCI-DSS v4.0

| Req | Title | Status |
|-----|-------|--------|
| 1.1 | Network security controls | Compliant |
| 2.1 | Secure configurations | Compliant |
| 5.1 | Malware protection | Compliant |
| 6.1 | Vulnerability management | Partially Compliant |
| 8.1 | Access controls | Compliant |
| 10.1 | Logging and monitoring | Compliant |
| 11.1 | Security testing | Non-Compliant |

**Summary:** 5/7 compliant, 1 partial, 1 non-compliant

**Critical Finding:** Requirement 11.1 — Penetration testing has not been conducted in the last 12 months. Schedule immediately.

**Partial Finding:** Requirement 6.1 — Vulnerability scans run monthly; PCI-DSS v4.0 recommends continuous or weekly scanning for critical assets.

## Configuration

```yaml
reporting:
  default_format: "markdown"
  include_raw_evidence: false
  max_timeline_events: 200
  compliance_frameworks:
    - GDPR
    - HIPAA
    - PCI-DSS
    - SOC2
    - NIST-CSF
  classification_default: "CONFIDENTIAL"
  retention_days: 365
```
