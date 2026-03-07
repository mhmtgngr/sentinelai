"""Tests for AI analyzer and notification manager."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from src.core.ai_analyzer import AIAnalyzer, AlertAnalysis, _ATTACK_PATTERNS
from src.core.config import LLMConfig
from src.core.event_bus import Event, EventBus, EventType
from src.core.notification_manager import (
    ChannelConfig,
    Notification,
    NotificationManager,
)


# ───────────── Fixtures ─────────────

@pytest_asyncio.fixture
async def event_bus():
    return EventBus()


@pytest.fixture
def llm_config_no_key():
    return LLMConfig(provider="claude", api_key="", model="claude-sonnet-4-20250514")


@pytest.fixture
def llm_config_claude():
    return LLMConfig(provider="claude", api_key="sk-test-key", model="claude-sonnet-4-20250514")


@pytest.fixture
def llm_config_openai():
    return LLMConfig(provider="openai", api_key="sk-test-key", model="gpt-4")


@pytest.fixture
def llm_config_ollama():
    return LLMConfig(provider="ollama", api_key="", model="llama3", ollama_base_url="http://localhost:11434")


@pytest.fixture
def sample_alert():
    return {
        "description": "Multiple failed login attempts detected from suspicious IP",
        "severity": "high",
        "source_ip": "10.0.0.99",
        "destination_ip": "192.168.1.10",
        "hostname": "DC-PROD-01",
        "username": "admin",
        "rule_name": "Brute Force Detection",
        "event_type": "authentication_failure",
    }


@pytest.fixture
def sample_malware_alert():
    return {
        "description": "Trojan backdoor detected on endpoint",
        "severity": "critical",
        "source_ip": "10.0.0.50",
        "hostname": "WS-USER-42",
        "rule_name": "Malware Detection",
        "file_hash": "abc123def456",
    }


# ───────────── AI Analyzer Tests ─────────────

class TestAIAnalyzerFallback:
    """Tests for rule-based fallback (no LLM API key)."""

    @pytest.mark.asyncio
    async def test_fallback_mode_no_key(self, llm_config_no_key, sample_alert):
        """Without API key, analyzer uses rule-based fallback."""
        analyzer = AIAnalyzer(llm_config_no_key)
        assert not analyzer.is_llm_available

        analysis = await analyzer.analyze_alert(sample_alert)
        assert isinstance(analysis, AlertAnalysis)
        assert analysis.analysis_source == "rule_based"
        assert analysis.attack_classification == "brute_force"
        assert analysis.threat_level == "high"
        assert len(analysis.mitre_techniques) > 0
        assert analysis.mitre_techniques[0]["id"] == "T1110"

    @pytest.mark.asyncio
    async def test_fallback_malware_detection(self, llm_config_no_key, sample_malware_alert):
        """Fallback correctly classifies malware."""
        analyzer = AIAnalyzer(llm_config_no_key)
        analysis = await analyzer.analyze_alert(sample_malware_alert)

        assert analysis.attack_classification == "malware"
        assert analysis.threat_level == "critical"
        assert "isolate_host" in analysis.recommended_actions

    @pytest.mark.asyncio
    async def test_fallback_unknown_attack(self, llm_config_no_key):
        """Unknown attack type when no keywords match."""
        analyzer = AIAnalyzer(llm_config_no_key)
        analysis = await analyzer.analyze_alert({
            "description": "Something unusual happened",
            "severity": "medium",
        })

        assert analysis.attack_classification == "unknown"
        assert analysis.analysis_source == "rule_based"
        assert "notify_soc" in analysis.recommended_actions

    @pytest.mark.asyncio
    async def test_ioc_extraction(self, llm_config_no_key, sample_alert):
        """IOCs are extracted from event data."""
        analyzer = AIAnalyzer(llm_config_no_key)
        analysis = await analyzer.analyze_alert(sample_alert)

        ioc_values = [ioc["value"] for ioc in analysis.indicators_of_compromise]
        assert "10.0.0.99" in ioc_values  # source_ip
        assert "192.168.1.10" in ioc_values  # destination_ip

    @pytest.mark.asyncio
    async def test_ioc_extraction_with_hash(self, llm_config_no_key, sample_malware_alert):
        """File hashes are extracted as IOCs."""
        analyzer = AIAnalyzer(llm_config_no_key)
        analysis = await analyzer.analyze_alert(sample_malware_alert)

        ioc_types = [ioc["type"] for ioc in analysis.indicators_of_compromise]
        assert "hash" in ioc_types

    @pytest.mark.asyncio
    async def test_fallback_narrative(self, llm_config_no_key):
        """Narrative generation without LLM."""
        analyzer = AIAnalyzer(llm_config_no_key)
        narrative = await analyzer.generate_incident_narrative({
            "attack_type": "brute_force",
            "severity": "high",
            "source_ip": "10.0.0.99",
            "hostname": "DC-01",
            "actions_executed": [{"action": "block_ip"}, {"action": "notify_soc"}],
        })

        assert "Brute Force" in narrative
        assert "10.0.0.99" in narrative
        assert "block_ip" in narrative

    @pytest.mark.asyncio
    async def test_fallback_decision_explanation(self, llm_config_no_key):
        """Decision explanation without LLM."""
        analyzer = AIAnalyzer(llm_config_no_key)
        explanation = await analyzer.explain_decision({
            "action": "isolate_host",
            "confidence": 0.92,
            "auto_approved": True,
            "reasoning": ["High confidence", "Known attack pattern"],
        })

        assert "isolate_host" in explanation
        assert "auto-approved" in explanation
        assert "92%" in explanation


class TestAIAnalyzerCaching:
    """Tests for caching behavior."""

    @pytest.mark.asyncio
    async def test_cache_hit(self, llm_config_no_key, sample_alert):
        """Same alert returns cached result."""
        analyzer = AIAnalyzer(llm_config_no_key)

        analysis1 = await analyzer.analyze_alert(sample_alert)
        analysis2 = await analyzer.analyze_alert(sample_alert)

        assert analyzer._stats["cache_hits"] == 1
        assert analysis1.attack_classification == analysis2.attack_classification

    @pytest.mark.asyncio
    async def test_cache_miss_different_alerts(self, llm_config_no_key, sample_alert, sample_malware_alert):
        """Different alerts are cached separately."""
        analyzer = AIAnalyzer(llm_config_no_key)

        await analyzer.analyze_alert(sample_alert)
        await analyzer.analyze_alert(sample_malware_alert)

        assert analyzer._stats["cache_hits"] == 0
        assert analyzer._stats["total_calls"] == 2


class TestAIAnalyzerLLM:
    """Tests for LLM integration (mocked)."""

    @pytest.mark.asyncio
    async def test_claude_call(self, llm_config_claude, sample_alert):
        """Claude API call returns structured analysis."""
        analyzer = AIAnalyzer(llm_config_claude)
        assert analyzer.is_llm_available

        mock_response = {
            "content": [{
                "text": '{"threat_level": "high", "explanation": "Brute force attack detected", '
                        '"attack_classification": "brute_force", '
                        '"mitre_techniques": [{"id": "T1110", "name": "Brute Force"}], '
                        '"recommended_actions": ["block_ip", "reset_credentials"], '
                        '"confidence": 0.9, '
                        '"indicators_of_compromise": [{"type": "ip", "value": "10.0.0.99"}]}'
            }],
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response
            mock_resp.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            analysis = await analyzer.analyze_alert(sample_alert)

        assert analysis.analysis_source == "llm"
        assert analysis.attack_classification == "brute_force"
        assert analysis.confidence == 0.9

    @pytest.mark.asyncio
    async def test_openai_call(self, llm_config_openai, sample_alert):
        """OpenAI API call returns structured analysis."""
        analyzer = AIAnalyzer(llm_config_openai)

        mock_response = {
            "choices": [{
                "message": {
                    "content": '{"threat_level": "high", "explanation": "Attack found", '
                               '"attack_classification": "brute_force", '
                               '"mitre_techniques": [], "recommended_actions": ["block_ip"], '
                               '"confidence": 0.85, "indicators_of_compromise": []}'
                }
            }],
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response
            mock_resp.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            analysis = await analyzer.analyze_alert(sample_alert)

        assert analysis.analysis_source == "llm"
        assert analysis.confidence == 0.85

    @pytest.mark.asyncio
    async def test_llm_error_fallback(self, llm_config_claude, sample_alert):
        """LLM error falls back to rule-based analysis."""
        analyzer = AIAnalyzer(llm_config_claude)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = Exception("API error")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            analysis = await analyzer.analyze_alert(sample_alert)

        assert analysis.analysis_source == "rule_based"
        assert analyzer._stats["errors"] == 1
        assert analyzer._stats["fallback_calls"] == 1

    @pytest.mark.asyncio
    async def test_llm_invalid_json_fallback(self, llm_config_claude, sample_alert):
        """Invalid LLM JSON response falls back to rule-based."""
        analyzer = AIAnalyzer(llm_config_claude)

        mock_response = {"content": [{"text": "This is not valid JSON at all"}]}

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_response
            mock_resp.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            analysis = await analyzer.analyze_alert(sample_alert)

        # Falls back to rule-based when JSON parsing fails
        assert analysis.analysis_source == "rule_based"

    @pytest.mark.asyncio
    async def test_ollama_available_without_key(self, llm_config_ollama):
        """Ollama is available without API key."""
        analyzer = AIAnalyzer(llm_config_ollama)
        assert analyzer.is_llm_available


class TestAIAnalyzerRateLimiting:
    """Tests for rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limit_check(self, llm_config_no_key):
        """Rate limit allows calls within limit."""
        analyzer = AIAnalyzer(llm_config_no_key)
        assert analyzer._check_rate_limit()

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self, llm_config_claude):
        """Rate limit blocks calls over limit."""
        analyzer = AIAnalyzer(llm_config_claude)
        # Fill up rate limit
        analyzer._call_timestamps = [time.time()] * 30

        # Should fall back to rule-based when rate limited
        analysis = await analyzer.analyze_alert({"description": "test", "severity": "low"})
        assert analysis.analysis_source == "rule_based"


class TestAIAnalyzerStats:
    """Tests for stats tracking."""

    @pytest.mark.asyncio
    async def test_stats_tracking(self, llm_config_no_key, sample_alert):
        """Stats are tracked correctly."""
        analyzer = AIAnalyzer(llm_config_no_key)
        await analyzer.analyze_alert(sample_alert)

        stats = analyzer.get_stats()
        assert stats["total_calls"] == 1
        assert stats["fallback_calls"] == 1
        assert stats["mode"] == "rule_based"
        assert stats["provider"] == "none"

    @pytest.mark.asyncio
    async def test_stats_with_llm(self, llm_config_claude):
        """Stats show LLM mode when key configured."""
        analyzer = AIAnalyzer(llm_config_claude)
        stats = analyzer.get_stats()
        assert stats["mode"] == "llm"
        assert stats["provider"] == "claude"


class TestAlertAnalysis:
    """Tests for AlertAnalysis dataclass."""

    def test_to_dict(self):
        analysis = AlertAnalysis(
            threat_level="high",
            explanation="Test alert",
            attack_classification="brute_force",
            mitre_techniques=[{"id": "T1110", "name": "Brute Force"}],
            recommended_actions=["block_ip"],
            confidence=0.9,
            indicators_of_compromise=[{"type": "ip", "value": "10.0.0.1"}],
            analysis_source="llm",
        )
        d = analysis.to_dict()
        assert d["threat_level"] == "high"
        assert d["confidence"] == 0.9
        assert d["analysis_source"] == "llm"
        assert len(d["mitre_techniques"]) == 1


# ───────────── Notification Manager Tests ─────────────

class TestNotificationManager:
    """Notification manager core functionality."""

    @pytest.mark.asyncio
    async def test_default_channels(self, event_bus):
        """Default config creates standard channels."""
        nm = NotificationManager(event_bus)
        nm._setup_defaults()

        assert "console" in nm._channels
        assert "teams_webhook" in nm._channels
        assert "websocket" in nm._channels
        assert "generic_webhook" in nm._channels

    @pytest.mark.asyncio
    async def test_severity_routing_critical(self, event_bus):
        """Critical alerts go to all channels."""
        nm = NotificationManager(event_bus)
        nm._setup_defaults()

        notification = Notification(
            title="Critical Alert",
            message="Test critical",
            severity="critical",
        )
        results = await nm.notify(notification)

        # Console should succeed (always works)
        assert results.get("console") is True

    @pytest.mark.asyncio
    async def test_severity_routing_low(self, event_bus):
        """Low severity only goes to console (Teams min_severity=high)."""
        nm = NotificationManager(event_bus)
        nm._setup_defaults()

        notification = Notification(
            title="Low Alert",
            message="Test low",
            severity="low",
        )
        results = await nm.notify(notification)

        assert results.get("console") is True
        # Teams should not be attempted (min_severity=high)
        assert "teams_webhook" not in results or results.get("teams_webhook") is False

    @pytest.mark.asyncio
    async def test_channel_disabled(self, event_bus):
        """Disabled channels are skipped."""
        nm = NotificationManager(event_bus)
        nm._channels = {
            "console": ChannelConfig(name="console", enabled=False, min_severity="low"),
        }

        notification = Notification(title="Test", message="Test", severity="critical")
        results = await nm.notify(notification)

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_throttling(self, event_bus):
        """Throttling limits notifications per channel per minute."""
        nm = NotificationManager(event_bus)
        nm._channels = {
            "console": ChannelConfig(name="console", enabled=True, min_severity="low"),
        }
        nm._throttle_max = 3

        notification = Notification(title="Test", message="Test", severity="high")

        # Send 3 notifications (within limit)
        for _ in range(3):
            results = await nm.notify(notification)
            assert results.get("console") is True

        # 4th should be throttled
        results = await nm.notify(notification)
        assert results.get("console") is False
        assert nm._stats["notifications_throttled"] > 0

    @pytest.mark.asyncio
    async def test_config_from_dict(self, event_bus):
        """Config can be applied from dict."""
        nm = NotificationManager(event_bus, config={
            "channels": {
                "console": {"enabled": True, "min_severity": "high"},
                "teams_webhook": {"enabled": False},
            },
            "throttle": {"max_per_channel_per_minute": 5},
        })

        assert nm._channels["console"].min_severity == "high"
        assert not nm._channels["teams_webhook"].enabled
        assert nm._throttle_max == 5

    @pytest.mark.asyncio
    async def test_load_config_missing_file(self, event_bus):
        """Missing config file falls back to defaults."""
        nm = NotificationManager(event_bus)
        nm.load_config("/nonexistent/path.yaml")

        assert "console" in nm._channels

    @pytest.mark.asyncio
    async def test_subscribe_events(self, event_bus):
        """Event subscription registers handlers."""
        nm = NotificationManager(event_bus)
        nm._setup_defaults()
        nm.subscribe_events()

        # Check that handlers are registered
        assert len(event_bus._subscribers.get(EventType.THREAT_DETECTED, [])) > 0
        assert len(event_bus._subscribers.get(EventType.ACTION_REQUESTED, [])) > 0

    @pytest.mark.asyncio
    async def test_threat_detected_event(self, event_bus):
        """THREAT_DETECTED event triggers notification."""
        nm = NotificationManager(event_bus)
        nm._channels = {
            "console": ChannelConfig(name="console", enabled=True, min_severity="low"),
        }
        nm.subscribe_events()

        event = Event(
            event_type=EventType.THREAT_DETECTED,
            data={
                "attack_type": "brute_force",
                "severity": "high",
                "source_ip": "10.0.0.99",
                "description": "Multiple failed logins",
            },
            source="triage",
        )
        await event_bus.publish(event)

        assert nm._stats["total_notifications"] > 0
        assert nm._stats["notifications_sent"] > 0

    @pytest.mark.asyncio
    async def test_action_requested_no_approval(self, event_bus):
        """ACTION_REQUESTED without requires_approval is ignored."""
        nm = NotificationManager(event_bus)
        nm._channels = {
            "console": ChannelConfig(name="console", enabled=True, min_severity="low"),
        }
        nm.subscribe_events()

        event = Event(
            event_type=EventType.ACTION_REQUESTED,
            data={"action": "notify_soc", "requires_approval": False},
            source="brain",
        )
        await event_bus.publish(event)

        assert nm._stats["total_notifications"] == 0

    @pytest.mark.asyncio
    async def test_action_requested_with_approval(self, event_bus):
        """ACTION_REQUESTED with requires_approval sends notification."""
        nm = NotificationManager(event_bus)
        nm._channels = {
            "console": ChannelConfig(name="console", enabled=True, min_severity="low"),
        }
        nm.subscribe_events()

        event = Event(
            event_type=EventType.ACTION_REQUESTED,
            data={
                "action": "isolate_host",
                "target": "WS-01",
                "requires_approval": True,
                "severity": "high",
                "confidence": 0.7,
                "escalation_reason": "destructive_action",
                "decision_id": "dec-123",
            },
            source="brain",
        )
        await event_bus.publish(event)

        assert nm._stats["total_notifications"] == 1

    @pytest.mark.asyncio
    async def test_generic_webhook_no_url(self, event_bus):
        """Generic webhook without URL configured returns False."""
        nm = NotificationManager(event_bus)
        nm._channels = {
            "generic_webhook": ChannelConfig(
                name="generic_webhook", enabled=True, min_severity="low", url="", url_env="NONEXISTENT_VAR",
            ),
        }

        notification = Notification(title="Test", message="Test", severity="high")
        results = await nm.notify(notification)
        assert results.get("generic_webhook") is False

    @pytest.mark.asyncio
    async def test_teams_webhook_no_url(self, event_bus):
        """Teams webhook without URL configured returns False."""
        nm = NotificationManager(event_bus)
        nm._channels = {
            "teams_webhook": ChannelConfig(
                name="teams_webhook", enabled=True, min_severity="low", url="", url_env="NONEXISTENT_TEAMS_VAR",
            ),
        }

        notification = Notification(title="Test", message="Test", severity="high")
        results = await nm.notify(notification)
        assert results.get("teams_webhook") is False

    @pytest.mark.asyncio
    async def test_stats(self, event_bus):
        """Stats are tracked correctly."""
        nm = NotificationManager(event_bus)
        nm._setup_defaults()
        stats = nm.get_stats()

        assert stats["total_notifications"] == 0
        assert "channels" in stats
        assert stats["throttle_limit"] == 10


class TestChannelConfig:
    """Tests for ChannelConfig."""

    def test_severity_acceptance(self):
        """Channel accepts correct severity levels."""
        ch = ChannelConfig(name="test", min_severity="high")
        assert ch.accepts_severity("critical") is True
        assert ch.accepts_severity("high") is True
        assert ch.accepts_severity("medium") is False
        assert ch.accepts_severity("low") is False

    def test_resolved_url_env(self):
        """URL resolved from env var."""
        import os
        os.environ["TEST_WEBHOOK_URL"] = "https://example.com/webhook"
        ch = ChannelConfig(name="test", url_env="TEST_WEBHOOK_URL")
        assert ch.resolved_url == "https://example.com/webhook"
        del os.environ["TEST_WEBHOOK_URL"]

    def test_resolved_url_direct(self):
        """URL used directly when no env var."""
        ch = ChannelConfig(name="test", url="https://direct.com/webhook")
        assert ch.resolved_url == "https://direct.com/webhook"


class TestNotification:
    """Tests for Notification dataclass."""

    def test_to_dict(self):
        n = Notification(
            title="Test Alert",
            message="Test message",
            severity="high",
            source="triage",
            ai_analysis={"explanation": "AI says this is bad"},
            recommended_actions=["block_ip"],
        )
        d = n.to_dict()
        assert d["title"] == "Test Alert"
        assert d["severity"] == "high"
        assert "ai_analysis" in d
        assert d["recommended_actions"] == ["block_ip"]

    def test_to_dict_minimal(self):
        n = Notification(title="Test", message="Msg", severity="low")
        d = n.to_dict()
        assert "ai_analysis" not in d
        assert "approval_id" not in d


# ───────────── Integration Tests ─────────────

class TestIntegration:
    """Integration tests for AI analyzer + notification manager + brain."""

    @pytest.mark.asyncio
    async def test_brain_has_ai_analyzer(self, event_bus):
        """Brain initializes AI analyzer."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)
        assert brain.ai_analyzer is not None
        assert isinstance(brain.ai_analyzer, AIAnalyzer)

    @pytest.mark.asyncio
    async def test_brain_has_notification_manager(self, event_bus):
        """Brain initializes notification manager."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)
        assert brain.notification_manager is not None
        assert isinstance(brain.notification_manager, NotificationManager)

    @pytest.mark.asyncio
    async def test_status_includes_ai_and_notifications(self, event_bus):
        """Brain status includes AI and notification stats."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)
        status = brain.get_status()

        assert "ai_analyzer" in status
        assert "notifications" in status
        assert "mode" in status["ai_analyzer"]

    @pytest.mark.asyncio
    async def test_triage_ai_enrichment(self, event_bus, sample_alert):
        """Triage agent enriches high-severity alerts with AI analysis."""
        from src.agents.triage_agent import TriageAgent

        triage = TriageAgent(event_bus, {"false_positive_patterns": []})
        await triage.initialize()

        # Inject a no-key analyzer (will use rule-based)
        triage.ai_analyzer = AIAnalyzer(LLMConfig(api_key=""))

        event = Event(
            event_type=EventType.ALERT_RECEIVED,
            data=sample_alert,
            source="test",
        )
        result = await triage.process(event)

        assert result.success
        # High severity + brute force pattern → should have AI analysis
        assert result.data.get("severity_score", 0) >= 75
        assert "ai_analysis" in result.data
        assert result.data["ai_analysis"]["attack_classification"] == "brute_force"

    @pytest.mark.asyncio
    async def test_triage_no_enrichment_low_severity(self, event_bus):
        """Low severity alerts are not AI-enriched."""
        from src.agents.triage_agent import TriageAgent

        triage = TriageAgent(event_bus, {"false_positive_patterns": []})
        await triage.initialize()
        triage.ai_analyzer = AIAnalyzer(LLMConfig(api_key=""))

        event = Event(
            event_type=EventType.ALERT_RECEIVED,
            data={
                "description": "Something mundane",
                "severity": "low",
                "source_ip": "10.0.0.1",
            },
            source="test",
        )
        result = await triage.process(event)

        assert result.success
        # Low severity → no AI enrichment
        assert "ai_analysis" not in result.data

    @pytest.mark.asyncio
    async def test_full_alert_flow(self, event_bus, sample_alert):
        """Full flow: alert → triage → AI enrichment → notification."""
        from src.agents.triage_agent import TriageAgent

        # Setup
        triage = TriageAgent(event_bus, {"false_positive_patterns": []})
        await triage.initialize()
        triage.ai_analyzer = AIAnalyzer(LLMConfig(api_key=""))

        nm = NotificationManager(event_bus)
        nm._channels = {
            "console": ChannelConfig(name="console", enabled=True, min_severity="low"),
        }
        nm.subscribe_events()

        # Triage the alert
        event = Event(
            event_type=EventType.ALERT_RECEIVED,
            data=sample_alert,
            source="test_adapter",
        )
        result = await triage.process(event)

        assert result.success
        assert "ai_analysis" in result.data

        # Notification should have been triggered by ALERT_ESCALATED event
        # (triage publishes ALERT_ESCALATED for severity_score >= 75)
        # The notification manager subscribes to THREAT_DETECTED, not ALERT_ESCALATED
        # So let's simulate the brain's _handle_alert behavior
        if result.data.get("severity_score", 0) >= 75:
            await event_bus.publish(Event(
                event_type=EventType.THREAT_DETECTED,
                data={
                    **result.data,
                    "learned_confidence": 0.8,
                },
                source="brain",
            ))

        # Notification manager should have processed the threat
        assert nm._stats["total_notifications"] > 0
