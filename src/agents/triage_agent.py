"""Autonomous triage agent that classifies, prioritizes, and routes alerts."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from src.core.config import settings, Severity as CfgSeverity
from src.core.event_bus import (
    event_bus,
    ALERT_RECEIVED,
    ALERT_TRIAGED,
    DECISION_NEEDED,
)
from src.core.models import (
    Alert,
    AlertCategory,
    AlertStatus,
    Severity,
    TriageResult,
)

logger = logging.getLogger(__name__)

# ── Keyword-based classification rules ──
CATEGORY_KEYWORDS: dict[AlertCategory, list[str]] = {
    AlertCategory.PHISHING: [
        "phish", "spoof", "credential harvest", "suspicious link", "impersonat",
        "social engineering", "deceptive email",
    ],
    AlertCategory.MALWARE: [
        "malware", "trojan", "virus", "worm", "ransomware", "payload",
        "malicious file", "dropper",
    ],
    AlertCategory.BRUTE_FORCE: [
        "brute force", "failed login", "password spray", "credential stuffing",
        "multiple failed", "login attempt",
    ],
    AlertCategory.DATA_EXFILTRATION: [
        "exfiltration", "data leak", "large upload", "unusual transfer",
        "sensitive data", "dlp",
    ],
    AlertCategory.UNAUTHORIZED_ACCESS: [
        "unauthorized", "privilege escalation", "admin access", "elevation",
        "bypass", "illegal access",
    ],
    AlertCategory.POLICY_VIOLATION: [
        "policy violation", "compliance", "prohibited", "unapproved software",
        "shadow it",
    ],
    AlertCategory.INSIDER_THREAT: [
        "insider", "unusual hours", "abnormal behavior", "terminated employee",
    ],
    AlertCategory.RANSOMWARE: [
        "ransomware", "encrypt", "ransom note", "file extension change",
    ],
    AlertCategory.LATERAL_MOVEMENT: [
        "lateral", "psexec", "wmi remote", "rdp brute", "pass the hash",
    ],
    AlertCategory.CREDENTIAL_COMPROMISE: [
        "credential leak", "password exposed", "dark web", "compromised account",
        "token theft",
    ],
    AlertCategory.VULNERABILITY: [
        "cve-", "vulnerability", "exploit", "unpatched", "zero-day",
    ],
}

# Severity escalation rules
SEVERITY_ESCALATION: dict[AlertCategory, Severity] = {
    AlertCategory.RANSOMWARE: Severity.CRITICAL,
    AlertCategory.DATA_EXFILTRATION: Severity.HIGH,
    AlertCategory.CREDENTIAL_COMPROMISE: Severity.HIGH,
    AlertCategory.LATERAL_MOVEMENT: Severity.HIGH,
}

# Categories that typically need user education
EDUCATION_CATEGORIES: set[AlertCategory] = {
    AlertCategory.PHISHING,
    AlertCategory.MALWARE,
    AlertCategory.POLICY_VIOLATION,
    AlertCategory.CREDENTIAL_COMPROMISE,
    AlertCategory.BRUTE_FORCE,
}

# Map categories to recommended SOAR actions
CATEGORY_ACTIONS: dict[AlertCategory, list[str]] = {
    AlertCategory.PHISHING: ["block_sender", "quarantine_email", "educate_user", "reset_password"],
    AlertCategory.MALWARE: ["isolate_endpoint", "quarantine_file", "scan_endpoint"],
    AlertCategory.BRUTE_FORCE: ["block_ip", "enforce_mfa", "educate_user"],
    AlertCategory.DATA_EXFILTRATION: ["block_transfer", "disable_account", "escalate"],
    AlertCategory.UNAUTHORIZED_ACCESS: ["disable_account", "revoke_sessions", "escalate"],
    AlertCategory.RANSOMWARE: ["isolate_endpoint", "disable_account", "escalate"],
    AlertCategory.LATERAL_MOVEMENT: ["isolate_endpoint", "block_ip", "escalate"],
    AlertCategory.CREDENTIAL_COMPROMISE: ["reset_password", "revoke_sessions", "educate_user"],
    AlertCategory.POLICY_VIOLATION: ["notify_manager", "educate_user"],
    AlertCategory.INSIDER_THREAT: ["monitor_user", "escalate"],
    AlertCategory.VULNERABILITY: ["patch_system", "isolate_endpoint"],
    AlertCategory.SUSPICIOUS_ACTIVITY: ["investigate", "monitor"],
}


class TriageAgent:
    """Autonomous alert triage — classifies, adjusts severity, recommends actions."""

    def __init__(self) -> None:
        event_bus.subscribe(ALERT_RECEIVED, self.handle_alert)

    def classify(self, alert: Alert) -> AlertCategory:
        """Classify an alert into a category based on keyword matching."""
        text = f"{alert.title} {alert.description}".lower()
        scores: dict[AlertCategory, int] = {}
        for category, keywords in CATEGORY_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in text)
            if score > 0:
                scores[category] = score
        if scores:
            return max(scores, key=scores.get)  # type: ignore[arg-type]
        return alert.category

    def adjust_severity(self, alert: Alert, category: AlertCategory) -> Severity:
        """Escalate severity based on category or context signals."""
        base = alert.severity
        escalated = SEVERITY_ESCALATION.get(category)
        if escalated and self._severity_rank(escalated) > self._severity_rank(base):
            logger.info(
                "Escalating alert %s severity %s -> %s (category: %s)",
                alert.id, base.value, escalated.value, category.value,
            )
            return escalated
        return base

    def triage(self, alert: Alert) -> TriageResult:
        """Full triage pipeline: classify -> adjust severity -> recommend actions."""
        category = self.classify(alert)
        adjusted_severity = self.adjust_severity(alert, category)
        actions = CATEGORY_ACTIONS.get(category, ["investigate"])
        education_needed = (
            category in EDUCATION_CATEGORIES and alert.affected_user is not None
        )
        education_topics = self._get_education_topics(category) if education_needed else []

        # Determine if human decision is required
        severity_threshold = CfgSeverity(
            settings.require_teams_approval_severity.value
        )
        requires_human = (
            self._severity_rank(adjusted_severity)
            >= self._severity_rank(Severity(severity_threshold.value))
        )
        if not settings.autonomous_mode:
            requires_human = True

        return TriageResult(
            alert_id=alert.id,
            original_severity=alert.severity,
            adjusted_severity=adjusted_severity,
            category=category,
            confidence=0.85,
            summary=self._build_summary(alert, category, adjusted_severity),
            recommended_actions=actions,
            requires_human_decision=requires_human,
            auto_remediation_possible=settings.auto_remediate and not requires_human,
            education_needed=education_needed,
            education_topics=education_topics,
        )

    async def handle_alert(self, data: dict) -> None:
        """Event handler: triage an incoming alert and publish results."""
        alert = Alert(**data["alert"])
        logger.info("Triaging alert %s: %s", alert.id, alert.title)

        result = self.triage(alert)

        alert.status = AlertStatus.TRIAGED
        alert.category = result.category
        alert.severity = result.adjusted_severity
        alert.recommended_actions = result.recommended_actions

        await event_bus.publish(ALERT_TRIAGED, {
            "alert": alert.model_dump(mode="json"),
            "triage": result.model_dump(mode="json"),
        })

        if result.requires_human_decision:
            await event_bus.publish(DECISION_NEEDED, {
                "alert": alert.model_dump(mode="json"),
                "triage": result.model_dump(mode="json"),
            })

    def _build_summary(
        self, alert: Alert, category: AlertCategory, severity: Severity
    ) -> str:
        parts = [
            f"[{severity.value.upper()}] {category.value.replace('_', ' ').title()}",
            f"detected from {alert.source or 'unknown source'}.",
        ]
        if alert.affected_user:
            parts.append(f"Affected user: {alert.affected_user}.")
        if alert.affected_endpoint:
            parts.append(f"Endpoint: {alert.affected_endpoint}.")
        if alert.affected_ip:
            parts.append(f"Source IP: {alert.affected_ip}.")
        return " ".join(parts)

    def _get_education_topics(self, category: AlertCategory) -> list[str]:
        mapping = {
            AlertCategory.PHISHING: [
                "recognizing_phishing_emails",
                "safe_link_practices",
                "reporting_suspicious_emails",
            ],
            AlertCategory.MALWARE: [
                "safe_download_practices",
                "recognizing_malicious_attachments",
                "endpoint_security_basics",
            ],
            AlertCategory.BRUTE_FORCE: [
                "strong_password_practices",
                "multi_factor_authentication",
                "account_security",
            ],
            AlertCategory.POLICY_VIOLATION: [
                "acceptable_use_policy",
                "data_handling_guidelines",
                "compliance_requirements",
            ],
            AlertCategory.CREDENTIAL_COMPROMISE: [
                "password_hygiene",
                "credential_reuse_risks",
                "multi_factor_authentication",
            ],
        }
        return mapping.get(category, ["general_security_awareness"])

    @staticmethod
    def _severity_rank(sev: Severity) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[sev.value]
