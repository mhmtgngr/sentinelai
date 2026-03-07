"""AI-powered alert analysis using LLM providers (Claude, OpenAI, Ollama).

Enriches security alerts with AI reasoning: threat assessment, IOC extraction,
MITRE mapping, and recommended actions. Falls back to rule-based analysis
when no LLM API key is configured.

Usage:
    analyzer = AIAnalyzer(config.llm)
    analysis = await analyzer.analyze_alert(event_data)
    narrative = await analyzer.generate_incident_narrative(incident_data)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from src.core.config import LLMConfig

logger = logging.getLogger(__name__)

# Rate limiting
_MAX_CALLS_PER_MINUTE = 30
_CACHE_TTL_SECONDS = 300  # 5 minutes

# Rule-based fallback patterns (reused from triage_agent.py)
_ATTACK_PATTERNS = {
    "brute_force": {
        "keywords": ["failed login", "authentication failure", "invalid credentials", "login attempt"],
        "mitre": [{"id": "T1110", "name": "Brute Force"}],
        "actions": ["block_ip", "reset_credentials", "notify_soc"],
    },
    "sql_injection": {
        "keywords": ["sql injection", "sqli", "union select", "or 1=1", "drop table"],
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
        "actions": ["block_ip", "isolate_host", "collect_forensics"],
    },
    "xss": {
        "keywords": ["cross-site scripting", "xss", "<script>", "javascript:"],
        "mitre": [{"id": "T1189", "name": "Drive-by Compromise"}],
        "actions": ["block_ip", "notify_soc"],
    },
    "lateral_movement": {
        "keywords": ["lateral movement", "pass-the-hash", "psexec", "wmi remote"],
        "mitre": [{"id": "T1021", "name": "Remote Services"}, {"id": "T1550", "name": "Use Alternate Authentication Material"}],
        "actions": ["isolate_host", "revoke_sessions", "collect_forensics", "notify_soc"],
    },
    "data_exfiltration": {
        "keywords": ["data exfiltration", "large upload", "unusual transfer", "dns tunnel"],
        "mitre": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}, {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}],
        "actions": ["block_ip", "isolate_host", "collect_forensics", "notify_soc"],
    },
    "malware": {
        "keywords": ["malware", "trojan", "ransomware", "backdoor", "c2 beacon"],
        "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}, {"id": "T1486", "name": "Data Encrypted for Impact"}],
        "actions": ["isolate_host", "run_antivirus_scan", "collect_forensics", "block_ip", "notify_soc"],
    },
    "privilege_escalation": {
        "keywords": ["privilege escalation", "sudo", "admin elevation", "token manipulation"],
        "mitre": [{"id": "T1068", "name": "Exploitation for Privilege Escalation"}, {"id": "T1134", "name": "Access Token Manipulation"}],
        "actions": ["isolate_host", "revoke_sessions", "collect_forensics", "notify_soc"],
    },
    "reconnaissance": {
        "keywords": ["port scan", "network scan", "enumeration", "fingerprinting"],
        "mitre": [{"id": "T1046", "name": "Network Service Discovery"}, {"id": "T1595", "name": "Active Scanning"}],
        "actions": ["add_to_watchlist", "notify_soc"],
    },
}

_SEVERITY_MAP = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}


@dataclass
class AlertAnalysis:
    """Structured result from AI alert analysis."""

    threat_level: str = "medium"
    explanation: str = ""
    attack_classification: str = "unknown"
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    confidence: float = 0.5
    indicators_of_compromise: list[dict[str, str]] = field(default_factory=list)
    analysis_source: str = "rule_based"  # "llm" or "rule_based"

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_level": self.threat_level,
            "explanation": self.explanation,
            "attack_classification": self.attack_classification,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "confidence": self.confidence,
            "indicators_of_compromise": self.indicators_of_compromise,
            "analysis_source": self.analysis_source,
        }


class AIAnalyzer:
    """Analyzes security alerts using LLM providers with rule-based fallback.

    Supports three providers via raw httpx (no SDK dependencies):
    - Claude (Anthropic): api.anthropic.com/v1/messages
    - OpenAI: api.openai.com/v1/chat/completions
    - Ollama: local instance, no API key needed
    """

    def __init__(self, llm_config: LLMConfig) -> None:
        self._config = llm_config
        self._llm_available = bool(llm_config.api_key) or llm_config.provider == "ollama"

        # Rate limiting
        self._call_timestamps: list[float] = []

        # Cache: hash → (analysis, timestamp)
        self._cache: dict[str, tuple[AlertAnalysis, float]] = {}

        # Stats
        self._stats = {
            "total_calls": 0,
            "llm_calls": 0,
            "fallback_calls": 0,
            "cache_hits": 0,
            "errors": 0,
        }

        if self._llm_available:
            logger.info("AI Analyzer initialized: provider=%s, model=%s", llm_config.provider, llm_config.model)
        else:
            logger.info("AI Analyzer initialized: fallback mode (no LLM API key configured)")

    @property
    def is_llm_available(self) -> bool:
        return self._llm_available

    async def analyze_alert(self, event_data: dict[str, Any]) -> AlertAnalysis:
        """Analyze a security alert using AI or rule-based fallback."""
        self._stats["total_calls"] += 1

        # Check cache
        cache_key = self._compute_cache_key(event_data)
        cached = self._get_cached(cache_key)
        if cached:
            self._stats["cache_hits"] += 1
            return cached

        # Try LLM analysis, fall back to rules
        if self._llm_available and self._check_rate_limit():
            try:
                analysis = await self._llm_analyze(event_data)
                self._stats["llm_calls"] += 1
            except Exception:
                logger.exception("LLM analysis failed, falling back to rule-based")
                self._stats["errors"] += 1
                analysis = self._rule_based_analyze(event_data)
                self._stats["fallback_calls"] += 1
        else:
            analysis = self._rule_based_analyze(event_data)
            self._stats["fallback_calls"] += 1

        self._cache[cache_key] = (analysis, time.time())
        return analysis

    async def generate_incident_narrative(self, incident_data: dict[str, Any]) -> str:
        """Generate a human-readable incident narrative."""
        if not self._llm_available or not self._check_rate_limit():
            return self._rule_based_narrative(incident_data)

        prompt = self._build_narrative_prompt(incident_data)
        try:
            response = await self._call_llm(prompt)
            self._stats["llm_calls"] += 1
            return response
        except Exception:
            logger.exception("LLM narrative generation failed")
            self._stats["errors"] += 1
            return self._rule_based_narrative(incident_data)

    async def explain_decision(self, decision_data: dict[str, Any]) -> str:
        """Explain why the system made a specific decision."""
        if not self._llm_available or not self._check_rate_limit():
            return self._rule_based_decision_explanation(decision_data)

        prompt = self._build_decision_prompt(decision_data)
        try:
            response = await self._call_llm(prompt)
            self._stats["llm_calls"] += 1
            return response
        except Exception:
            logger.exception("LLM decision explanation failed")
            self._stats["errors"] += 1
            return self._rule_based_decision_explanation(decision_data)

    def get_stats(self) -> dict[str, Any]:
        """Return analyzer statistics."""
        return {
            **self._stats,
            "mode": "llm" if self._llm_available else "rule_based",
            "provider": self._config.provider if self._llm_available else "none",
            "model": self._config.model if self._llm_available else "none",
            "cache_size": len(self._cache),
        }

    # ───────────── LLM Calls ─────────────

    async def _llm_analyze(self, event_data: dict[str, Any]) -> AlertAnalysis:
        """Call LLM for alert analysis."""
        prompt = self._build_analysis_prompt(event_data)
        response_text = await self._call_llm(prompt)
        return self._parse_llm_response(response_text, event_data)

    async def _call_llm(self, prompt: str) -> str:
        """Send prompt to configured LLM provider and return response text."""
        self._record_call()

        provider = self._config.provider
        if provider == "claude":
            return await self._call_claude(prompt)
        elif provider == "openai":
            return await self._call_openai(prompt)
        elif provider == "ollama":
            return await self._call_ollama(prompt)
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")

    async def _call_claude(self, prompt: str) -> str:
        """Call Claude API via httpx."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._config.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self._config.model,
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]

    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API via httpx."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._config.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._config.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1024,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def _call_ollama(self, prompt: str) -> str:
        """Call Ollama local API via httpx."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self._config.ollama_base_url}/api/generate",
                json={
                    "model": self._config.model,
                    "prompt": prompt,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "")

    # ───────────── Prompt Building ─────────────

    def _build_analysis_prompt(self, event_data: dict[str, Any]) -> str:
        """Build prompt for alert analysis."""
        return f"""You are a senior SOC analyst. Analyze this security alert and respond with a JSON object.

Alert Data:
- Description: {event_data.get('description', 'N/A')}
- Severity: {event_data.get('severity', 'N/A')}
- Source IP: {event_data.get('source_ip', 'N/A')}
- Destination IP: {event_data.get('destination_ip', 'N/A')}
- Hostname: {event_data.get('hostname', 'N/A')}
- Username: {event_data.get('username', 'N/A')}
- Rule Name: {event_data.get('rule_name', 'N/A')}
- Event Type: {event_data.get('event_type', 'N/A')}
- Raw Data: {json.dumps({k: v for k, v in event_data.items() if k not in ('description', 'severity', 'source_ip', 'destination_ip', 'hostname', 'username', 'rule_name', 'event_type')}, default=str)[:500]}

Respond with ONLY a JSON object (no markdown, no explanation outside JSON):
{{
    "threat_level": "critical|high|medium|low",
    "explanation": "2-3 sentence explanation of what happened and why it matters",
    "attack_classification": "brute_force|sql_injection|xss|lateral_movement|data_exfiltration|malware|privilege_escalation|reconnaissance|unknown",
    "mitre_techniques": [{{"id": "T1234", "name": "Technique Name"}}],
    "recommended_actions": ["action1", "action2"],
    "confidence": 0.85,
    "indicators_of_compromise": [{{"type": "ip|domain|hash|url|email", "value": "..."}}]
}}"""

    def _build_narrative_prompt(self, incident_data: dict[str, Any]) -> str:
        return f"""You are a senior SOC analyst writing an incident report. Create a clear, concise narrative summary.

Incident Data:
{json.dumps(incident_data, default=str, indent=2)[:2000]}

Write a 3-5 paragraph incident narrative covering:
1. What happened (timeline and sequence of events)
2. What was affected (systems, users, data)
3. What actions were taken (automated and manual)
4. Current status and recommended next steps

Be factual and specific. Use the data provided."""

    def _build_decision_prompt(self, decision_data: dict[str, Any]) -> str:
        return f"""You are a security automation system explaining a decision. Provide a clear explanation.

Decision Data:
{json.dumps(decision_data, default=str, indent=2)[:2000]}

Explain in 2-3 sentences:
1. What action was proposed and why
2. Whether it was auto-approved or escalated to a human, and the reasoning
3. What confidence level drove the decision"""

    # ───────────── Response Parsing ─────────────

    def _parse_llm_response(self, response_text: str, event_data: dict[str, Any]) -> AlertAnalysis:
        """Parse LLM JSON response into AlertAnalysis."""
        try:
            # Try to extract JSON from response
            text = response_text.strip()
            # Handle markdown code blocks
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()

            data = json.loads(text)
            return AlertAnalysis(
                threat_level=data.get("threat_level", "medium"),
                explanation=data.get("explanation", ""),
                attack_classification=data.get("attack_classification", "unknown"),
                mitre_techniques=data.get("mitre_techniques", []),
                recommended_actions=data.get("recommended_actions", []),
                confidence=float(data.get("confidence", 0.7)),
                indicators_of_compromise=data.get("indicators_of_compromise", []),
                analysis_source="llm",
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            logger.warning("Failed to parse LLM response, falling back to rule-based")
            return self._rule_based_analyze(event_data)

    # ───────────── Rule-Based Fallback ─────────────

    def _rule_based_analyze(self, event_data: dict[str, Any]) -> AlertAnalysis:
        """Enhanced rule-based analysis (no LLM needed)."""
        desc = (event_data.get("description", "") + " " + event_data.get("rule_name", "")).lower()
        severity = event_data.get("severity", "medium")

        # Classify attack
        attack_type = "unknown"
        mitre_techniques: list[dict[str, str]] = []
        recommended_actions: list[str] = ["notify_soc"]

        for atype, pattern_info in _ATTACK_PATTERNS.items():
            if any(kw in desc for kw in pattern_info["keywords"]):
                attack_type = atype
                mitre_techniques = pattern_info["mitre"]
                recommended_actions = pattern_info["actions"]
                break

        # Calculate confidence based on severity and pattern match
        base_confidence = _SEVERITY_MAP.get(severity, 0.5)
        if attack_type != "unknown":
            confidence = min(0.95, base_confidence + 0.2)
        else:
            confidence = base_confidence * 0.8

        # Extract IOCs from event data
        iocs = self._extract_iocs(event_data)

        # Build explanation
        if attack_type != "unknown":
            explanation = (
                f"Alert indicates a potential {attack_type.replace('_', ' ')} attack. "
                f"Source: {event_data.get('source_ip', 'unknown')}. "
                f"Severity assessed as {severity}."
            )
        else:
            explanation = (
                f"Security alert received with {severity} severity. "
                f"Source: {event_data.get('source_ip', 'unknown')}. "
                f"Further investigation recommended."
            )

        return AlertAnalysis(
            threat_level=severity,
            explanation=explanation,
            attack_classification=attack_type,
            mitre_techniques=mitre_techniques,
            recommended_actions=recommended_actions,
            confidence=confidence,
            indicators_of_compromise=iocs,
            analysis_source="rule_based",
        )

    def _rule_based_narrative(self, incident_data: dict[str, Any]) -> str:
        """Generate incident narrative without LLM."""
        attack_type = incident_data.get("attack_type", "unknown")
        severity = incident_data.get("severity", "medium")
        source_ip = incident_data.get("source_ip", "unknown")
        hostname = incident_data.get("hostname", "unknown")
        actions = incident_data.get("actions_executed", [])

        action_list = ", ".join(
            a.get("action", "unknown") if isinstance(a, dict) else str(a)
            for a in actions
        ) if actions else "none"

        return (
            f"Incident Report: {attack_type.replace('_', ' ').title()} attack detected.\n\n"
            f"A {severity} severity {attack_type.replace('_', ' ')} attack was detected "
            f"originating from {source_ip} targeting {hostname}. "
            f"The following automated actions were executed: {action_list}. "
            f"Review the incident timeline and confirm the response was appropriate."
        )

    def _rule_based_decision_explanation(self, decision_data: dict[str, Any]) -> str:
        """Explain a decision without LLM."""
        action = decision_data.get("action", "unknown")
        confidence = decision_data.get("confidence", 0)
        auto_approved = decision_data.get("auto_approved", False)
        reasoning = decision_data.get("reasoning", [])

        status = "auto-approved" if auto_approved else "escalated to human operator"
        reason_text = "; ".join(reasoning[:3]) if reasoning else "standard policy"

        return (
            f"Action '{action}' was {status} with {confidence:.0%} confidence. "
            f"Reasoning: {reason_text}."
        )

    # ───────────── IOC Extraction ─────────────

    def _extract_iocs(self, event_data: dict[str, Any]) -> list[dict[str, str]]:
        """Extract indicators of compromise from event data."""
        iocs: list[dict[str, str]] = []

        ip_fields = ["source_ip", "destination_ip", "attacker_ip", "target_ip"]
        for f in ip_fields:
            val = event_data.get(f)
            if val and val not in ("unknown", "N/A", ""):
                iocs.append({"type": "ip", "value": val})

        domain_fields = ["domain", "hostname", "target_host"]
        for f in domain_fields:
            val = event_data.get(f)
            if val and val not in ("unknown", "N/A", ""):
                iocs.append({"type": "domain", "value": val})

        hash_fields = ["file_hash", "md5", "sha256", "sha1"]
        for f in hash_fields:
            val = event_data.get(f)
            if val:
                iocs.append({"type": "hash", "value": val})

        url_fields = ["url", "request_url"]
        for f in url_fields:
            val = event_data.get(f)
            if val:
                iocs.append({"type": "url", "value": val})

        return iocs

    # ───────────── Rate Limiting & Caching ─────────────

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limit."""
        now = time.time()
        self._call_timestamps = [t for t in self._call_timestamps if now - t < 60]
        return len(self._call_timestamps) < _MAX_CALLS_PER_MINUTE

    def _record_call(self) -> None:
        """Record an API call timestamp."""
        self._call_timestamps.append(time.time())

    def _compute_cache_key(self, event_data: dict[str, Any]) -> str:
        """Compute cache key from event data."""
        key_fields = ["description", "source_ip", "rule_name", "severity", "event_type"]
        key_str = "|".join(str(event_data.get(f, "")) for f in key_fields)
        return hashlib.md5(key_str.encode()).hexdigest()

    def _get_cached(self, cache_key: str) -> AlertAnalysis | None:
        """Get cached analysis if not expired."""
        if cache_key in self._cache:
            analysis, timestamp = self._cache[cache_key]
            if time.time() - timestamp < _CACHE_TTL_SECONDS:
                return analysis
            del self._cache[cache_key]
        return None
