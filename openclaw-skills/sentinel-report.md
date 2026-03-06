# Sentinel-AI: Security Reporting Skill

## Description
Generates comprehensive security reports including compliance audits, vulnerability assessments, incident summaries, and threat landscape analysis.

## Trigger
- Scheduled (daily, weekly, monthly)
- On-demand request
- After major incident closure

## Report Types

### Daily Security Summary
- Alert volume and triage statistics
- New incidents and resolutions
- Top threat sources
- UEBA anomalies detected

### Compliance Audit Report
- Framework coverage (CIS, SOC2, GDPR, PCI-DSS)
- Pass/fail per control
- Compliance score trends
- Remediation recommendations

### Vulnerability Assessment Report
- New vulnerabilities discovered
- Severity distribution
- Remediation status
- Risk scoring

### Incident Post-Mortem
- Incident timeline reconstruction
- Attack path analysis (from knowledge graph)
- IOCs extracted
- Lessons learned
- Detection improvement recommendations

## Parameters
- `report_type`: Type of report to generate
- `time_range`: Period to cover
- `format`: Output format (json, markdown, pdf)
- `recipients`: Distribution list
