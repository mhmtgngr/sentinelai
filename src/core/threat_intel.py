"""Threat intelligence enrichment — correlates alerts with known threat data."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.core.models import Alert, AlertCategory, Severity

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """A single indicator of compromise (IOC)."""
    value: str
    indicator_type: str  # ip, domain, hash, email, url
    threat_name: str = ""
    severity: str = "medium"
    source: str = "internal"
    tags: list[str] = field(default_factory=list)
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class EnrichmentResult:
    """Result of enriching an alert with threat intelligence."""
    alert_id: str
    matched_indicators: list[ThreatIndicator] = field(default_factory=list)
    risk_score: float = 0.0
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    recommended_severity: Severity | None = None
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def has_matches(self) -> bool:
        return len(self.matched_indicators) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "matched_indicators": [
                {"value": i.value, "type": i.indicator_type, "threat": i.threat_name,
                 "severity": i.severity, "source": i.source}
                for i in self.matched_indicators
            ],
            "risk_score": self.risk_score,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "recommended_severity": self.recommended_severity.value if self.recommended_severity else None,
            "context": self.context,
        }


# MITRE ATT&CK mapping for alert categories
CATEGORY_MITRE_MAP: dict[AlertCategory, dict[str, list[str]]] = {
    AlertCategory.PHISHING: {
        "tactics": ["Initial Access"],
        "techniques": ["T1566 - Phishing", "T1566.001 - Spearphishing Attachment",
                       "T1566.002 - Spearphishing Link"],
    },
    AlertCategory.MALWARE: {
        "tactics": ["Execution", "Persistence"],
        "techniques": ["T1059 - Command and Scripting Interpreter",
                       "T1204 - User Execution"],
    },
    AlertCategory.BRUTE_FORCE: {
        "tactics": ["Credential Access"],
        "techniques": ["T1110 - Brute Force", "T1110.001 - Password Guessing",
                       "T1110.003 - Password Spraying"],
    },
    AlertCategory.DATA_EXFILTRATION: {
        "tactics": ["Exfiltration"],
        "techniques": ["T1041 - Exfiltration Over C2 Channel",
                       "T1567 - Exfiltration Over Web Service"],
    },
    AlertCategory.UNAUTHORIZED_ACCESS: {
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "techniques": ["T1078 - Valid Accounts", "T1548 - Abuse Elevation Control"],
    },
    AlertCategory.RANSOMWARE: {
        "tactics": ["Impact"],
        "techniques": ["T1486 - Data Encrypted for Impact",
                       "T1490 - Inhibit System Recovery"],
    },
    AlertCategory.LATERAL_MOVEMENT: {
        "tactics": ["Lateral Movement"],
        "techniques": ["T1021 - Remote Services", "T1550 - Use Alternate Authentication"],
    },
    AlertCategory.CREDENTIAL_COMPROMISE: {
        "tactics": ["Credential Access"],
        "techniques": ["T1003 - OS Credential Dumping",
                       "T1555 - Credentials from Password Stores"],
    },
    AlertCategory.INSIDER_THREAT: {
        "tactics": ["Collection", "Exfiltration"],
        "techniques": ["T1074 - Data Staged", "T1005 - Data from Local System"],
    },
    AlertCategory.VULNERABILITY: {
        "tactics": ["Initial Access"],
        "techniques": ["T1190 - Exploit Public-Facing Application"],
    },
}


class ThreatIntelEngine:
    """Correlates alerts against known threat indicators and MITRE ATT&CK."""

    def __init__(self) -> None:
        self._indicators: dict[str, ThreatIndicator] = {}
        self._enrichment_log: list[EnrichmentResult] = []

    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Register a threat indicator."""
        self._indicators[indicator.value.lower()] = indicator

    def add_indicators(self, indicators: list[ThreatIndicator]) -> None:
        for ind in indicators:
            self.add_indicator(ind)

    def enrich(self, alert: Alert) -> EnrichmentResult:
        """Enrich an alert with threat intelligence and MITRE mapping."""
        result = EnrichmentResult(alert_id=alert.id)

        # Match indicators against alert fields
        search_values = [
            v for v in [alert.affected_ip, alert.affected_user,
                        alert.affected_endpoint] if v
        ]
        # Also check raw_data for IPs, domains, hashes
        for key in ("src_ip", "dst_ip", "sender", "domain", "file_hash", "url"):
            val = alert.raw_data.get(key)
            if val:
                search_values.append(str(val))

        for val in search_values:
            indicator = self._indicators.get(val.lower())
            if indicator:
                result.matched_indicators.append(indicator)

        # Compute risk score
        result.risk_score = self._compute_risk_score(alert, result)

        # Map to MITRE ATT&CK
        mitre = CATEGORY_MITRE_MAP.get(alert.category, {})
        result.mitre_tactics = mitre.get("tactics", [])
        result.mitre_techniques = mitre.get("techniques", [])

        # Recommend severity upgrade if high-risk indicators found
        if result.risk_score >= 0.8:
            result.recommended_severity = Severity.CRITICAL
        elif result.risk_score >= 0.6:
            result.recommended_severity = Severity.HIGH

        self._enrichment_log.append(result)
        if result.has_matches:
            logger.info(
                "ThreatIntel: alert %s matched %d indicator(s), risk=%.2f",
                alert.id, len(result.matched_indicators), result.risk_score,
            )
        return result

    def _compute_risk_score(self, alert: Alert, enrichment: EnrichmentResult) -> float:
        """Compute a 0.0-1.0 risk score based on multiple factors."""
        score = 0.0

        # Base score from severity
        severity_scores = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 0.8}
        score += severity_scores.get(alert.severity.value, 0.3)

        # Boost for matched indicators
        score += min(len(enrichment.matched_indicators) * 0.15, 0.3)

        # Boost for high-risk categories
        high_risk = {AlertCategory.RANSOMWARE, AlertCategory.DATA_EXFILTRATION,
                     AlertCategory.LATERAL_MOVEMENT}
        if alert.category in high_risk:
            score += 0.1

        return min(score, 1.0)

    @property
    def indicator_count(self) -> int:
        return len(self._indicators)

    @property
    def enrichment_count(self) -> int:
        return len(self._enrichment_log)
