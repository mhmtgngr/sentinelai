"""Alert triage & prioritization agent."""

from __future__ import annotations

import logging
from typing import Any

from src.agents.base_agent import AgentCapability, AgentResult, BaseAgent
from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)

# Severity scoring weights
SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}

# Known attack pattern keywords for quick classification
ATTACK_PATTERNS = {
    "brute_force": ["failed login", "authentication failure", "invalid credentials", "login attempt"],
    "sql_injection": ["sql injection", "sqli", "union select", "or 1=1", "drop table"],
    "xss": ["cross-site scripting", "xss", "<script>", "javascript:"],
    "lateral_movement": ["lateral movement", "pass-the-hash", "psexec", "wmi remote"],
    "data_exfiltration": ["data exfiltration", "large upload", "unusual transfer", "dns tunnel"],
    "malware": ["malware", "trojan", "ransomware", "backdoor", "c2 beacon"],
    "privilege_escalation": ["privilege escalation", "sudo", "admin elevation", "token manipulation"],
    "reconnaissance": ["port scan", "network scan", "enumeration", "fingerprinting"],
}


class TriageAgent(BaseAgent):
    """Triages incoming security alerts by severity, deduplication, and pattern matching."""

    name = "triage"
    capability = AgentCapability.TRIAGE

    def __init__(self, event_bus: EventBus, config: dict | None = None) -> None:
        super().__init__(event_bus, config)
        self._alert_cache: dict[str, dict[str, Any]] = {}
        self._false_positive_patterns: list[str] = []

    async def initialize(self) -> None:
        await super().initialize()
        self._false_positive_patterns = self.config.get("false_positive_patterns", [])

    async def process(self, event: Event) -> AgentResult:
        """Triage an incoming alert: score, classify, deduplicate, and route."""
        alert_data = event.data
        alert_key = self._compute_alert_key(alert_data)

        # Deduplication
        if alert_key in self._alert_cache:
            self._alert_cache[alert_key]["count"] = self._alert_cache[alert_key].get("count", 1) + 1
            return AgentResult(
                agent_name=self.name,
                action="deduplicate",
                success=True,
                data={"alert_key": alert_key, "duplicate_count": self._alert_cache[alert_key]["count"]},
            )

        # False positive check
        if self._is_false_positive(alert_data):
            await self.event_bus.publish(Event(
                event_type=EventType.ALERT_FALSE_POSITIVE,
                data=alert_data,
                source=self.name,
            ))
            return AgentResult(
                agent_name=self.name,
                action="false_positive",
                success=True,
                data={"reason": "Matched known false positive pattern"},
            )

        # Score and classify
        severity_score = self._calculate_severity(alert_data)
        attack_type = self._classify_attack(alert_data)
        mitre_tactics = self._map_mitre_tactics(attack_type)

        enriched = {
            **alert_data,
            "severity_score": severity_score,
            "attack_type": attack_type,
            "mitre_tactics": mitre_tactics,
            "triaged_by": self.name,
        }

        self._alert_cache[alert_key] = enriched

        # Route based on severity
        if severity_score >= 75:
            await self.event_bus.publish(Event(
                event_type=EventType.ALERT_ESCALATED,
                data=enriched,
                source=self.name,
            ))
        else:
            await self.event_bus.publish(Event(
                event_type=EventType.ALERT_TRIAGED,
                data=enriched,
                source=self.name,
            ))

        return AgentResult(
            agent_name=self.name,
            action="triage",
            success=True,
            data=enriched,
        )

    async def run_autonomous(self) -> list[AgentResult]:
        """Review cached alerts for pattern correlation."""
        results = []
        correlated = self._correlate_alerts()
        for group_key, alerts in correlated.items():
            if len(alerts) >= 3:
                await self.event_bus.publish(Event(
                    event_type=EventType.THREAT_DETECTED,
                    data={
                        "type": "correlated_alerts",
                        "group": group_key,
                        "alert_count": len(alerts),
                        "severity": "high",
                    },
                    source=self.name,
                ))
                results.append(AgentResult(
                    agent_name=self.name,
                    action="correlate",
                    success=True,
                    data={"group": group_key, "count": len(alerts)},
                ))
        return results

    def _compute_alert_key(self, alert_data: dict) -> str:
        src = alert_data.get("source_ip", "")
        rule = alert_data.get("rule_id", "")
        desc = alert_data.get("description", "")[:50]
        return f"{src}:{rule}:{desc}"

    def _is_false_positive(self, alert_data: dict) -> bool:
        desc = alert_data.get("description", "").lower()
        return any(pattern.lower() in desc for pattern in self._false_positive_patterns)

    def _calculate_severity(self, alert_data: dict) -> int:
        base = SEVERITY_WEIGHTS.get(alert_data.get("severity", "info"), 10)
        # Boost for known attack types
        if self._classify_attack(alert_data) != "unknown":
            base = min(100, base + 15)
        # Boost for internal targets
        if alert_data.get("target_is_internal", False):
            base = min(100, base + 10)
        return base

    def _classify_attack(self, alert_data: dict) -> str:
        desc = (alert_data.get("description", "") + " " + alert_data.get("rule_name", "")).lower()
        for attack_type, keywords in ATTACK_PATTERNS.items():
            if any(kw in desc for kw in keywords):
                return attack_type
        return "unknown"

    def _map_mitre_tactics(self, attack_type: str) -> list[str]:
        mapping = {
            "brute_force": ["TA0006-Credential Access"],
            "sql_injection": ["TA0001-Initial Access"],
            "xss": ["TA0001-Initial Access"],
            "lateral_movement": ["TA0008-Lateral Movement"],
            "data_exfiltration": ["TA0010-Exfiltration"],
            "malware": ["TA0002-Execution"],
            "privilege_escalation": ["TA0004-Privilege Escalation"],
            "reconnaissance": ["TA0043-Reconnaissance"],
        }
        return mapping.get(attack_type, [])

    def _correlate_alerts(self) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = {}
        for alert in self._alert_cache.values():
            source_ip = alert.get("source_ip", "unknown")
            if source_ip not in groups:
                groups[source_ip] = []
            groups[source_ip].append(alert)
        return groups
