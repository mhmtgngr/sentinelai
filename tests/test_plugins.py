"""Tests for plugin manager and extensibility system."""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
import yaml

from src.core.event_bus import EventBus
from src.core.plugin_manager import PluginManager
from src.agents.base_agent import BaseAgent, AgentCapability, AgentResult
from src.core.event_bus import Event


# ───────────── Fixtures ─────────────

@pytest_asyncio.fixture
async def event_bus():
    return EventBus()


@pytest_asyncio.fixture
async def plugin_manager(event_bus):
    return PluginManager(event_bus)


# ───────────── Plugin Manager Tests ─────────────

class TestPluginManager:
    """Plugin manager core functionality."""

    @pytest.mark.asyncio
    async def test_register_agent(self, plugin_manager, event_bus):
        """Register a custom agent class."""

        class CustomAgent(BaseAgent):
            name = "custom"
            capability = AgentCapability.TRIAGE

            async def process(self, event):
                return AgentResult(agent_name=self.name, action="test", success=True)

            async def run_autonomous(self):
                return []

        plugin_manager.register_agent("custom", CustomAgent)
        agent = plugin_manager.create_agent("custom")
        assert agent.name == "custom"
        assert isinstance(agent, BaseAgent)

    @pytest.mark.asyncio
    async def test_register_agent_invalid_class(self, plugin_manager):
        """Reject non-BaseAgent classes."""
        with pytest.raises(TypeError):
            plugin_manager.register_agent("bad", dict)

    @pytest.mark.asyncio
    async def test_create_unknown_agent(self, plugin_manager):
        """Creating unknown agent raises ValueError."""
        with pytest.raises(ValueError):
            plugin_manager.create_agent("nonexistent")

    @pytest.mark.asyncio
    async def test_register_adapter(self, plugin_manager):
        """Register a custom adapter class."""
        from src.integrations.base_adapter import BaseSecurityAdapter

        class CustomAdapter(BaseSecurityAdapter):
            vendor = "custom_vendor"
            product_type = "test"

            async def _authenticate(self):
                return True

            async def get_events(self):
                return []

            async def health_check(self):
                return {"status": "healthy"}

        plugin_manager.register_adapter("custom_vendor", CustomAdapter)
        adapter = plugin_manager.create_adapter("custom_vendor", {"name": "test"})
        assert adapter.vendor == "custom_vendor"

    @pytest.mark.asyncio
    async def test_load_technique_pack(self, plugin_manager):
        """Load technique pack from YAML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tech_file = Path(tmpdir) / "custom_techs.yaml"
            tech_file.write_text(yaml.dump({
                "name": "test_pack",
                "techniques": {
                    "T9001": {
                        "name": "Custom Test Technique",
                        "tactic": "execution",
                        "description": "A test technique",
                        "platforms": ["windows"],
                        "simulation_indicators": {"event_type": "test"},
                        "detection_sources": ["test_source"],
                    },
                    "T9002": {
                        "name": "Another Test",
                        "tactic": "persistence",
                        "description": "Another test",
                        "platforms": ["linux"],
                        "simulation_indicators": {},
                        "detection_sources": [],
                    },
                },
            }))

            loaded = plugin_manager.load_technique_packs(tmpdir)
            assert loaded == 2

            all_techs = plugin_manager.get_all_techniques()
            assert "T9001" in all_techs
            assert all_techs["T9001"]["name"] == "Custom Test Technique"

    @pytest.mark.asyncio
    async def test_load_technique_pack_nonexistent_dir(self, plugin_manager):
        """Loading from nonexistent directory returns 0."""
        loaded = plugin_manager.load_technique_packs("/nonexistent/path")
        assert loaded == 0

    @pytest.mark.asyncio
    async def test_load_stride_templates(self, plugin_manager):
        """Load custom STRIDE templates from YAML."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stride_file = Path(tmpdir) / "database.yaml"
            stride_file.write_text(yaml.dump({
                "asset_type": "database",
                "threats": [
                    {
                        "category": "information_disclosure",
                        "title": "Database Breach",
                        "description": "Data stolen from database",
                        "likelihood": 4,
                        "impact": 5,
                        "mitre_techniques": ["T1213"],
                        "mitigations": ["Encrypt at rest"],
                    },
                ],
            }))

            loaded = plugin_manager.load_stride_templates(tmpdir)
            assert loaded == 1

            all_templates = plugin_manager.get_all_stride_templates()
            assert "database" in all_templates
            assert len(all_templates["database"]) == 1

    @pytest.mark.asyncio
    async def test_register_hook(self, plugin_manager):
        """Register event hooks."""
        called = []

        async def my_hook(event):
            called.append(event)

        plugin_manager.register_hook("threat.detected", my_hook)
        hooks = plugin_manager.get_hooks("threat.detected")
        assert len(hooks) == 1

    @pytest.mark.asyncio
    async def test_load_all(self, plugin_manager):
        """Load all plugins from config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tech_dir = Path(tmpdir) / "techniques"
            tech_dir.mkdir()

            tech_file = tech_dir / "pack.yaml"
            tech_file.write_text(yaml.dump({
                "name": "test",
                "techniques": {
                    "T9999": {
                        "name": "Test",
                        "tactic": "execution",
                        "description": "Test",
                        "platforms": ["windows"],
                        "simulation_indicators": {},
                        "detection_sources": [],
                    },
                },
            }))

            results = plugin_manager.load_all({
                "technique_packs": [str(tech_dir)],
            })
            assert results["techniques"] == 1

    @pytest.mark.asyncio
    async def test_get_stats(self, plugin_manager):
        """Plugin stats are tracked."""
        stats = plugin_manager.get_stats()
        assert stats["agent_plugins"] == 0
        assert stats["total_plugins_loaded"] == 0

    @pytest.mark.asyncio
    async def test_loaded_plugins_tracking(self, plugin_manager, event_bus):
        """Plugin loading is tracked."""

        class TestAgent(BaseAgent):
            name = "tracker_test"
            capability = AgentCapability.TRIAGE

            async def process(self, event):
                return AgentResult(agent_name=self.name, action="test", success=True)

            async def run_autonomous(self):
                return []

        plugin_manager.register_agent("tracker_test", TestAgent)
        plugins = plugin_manager.get_loaded_plugins()
        assert len(plugins) == 1
        assert plugins[0]["type"] == "agent"
        assert plugins[0]["name"] == "tracker_test"

    @pytest.mark.asyncio
    async def test_discover_agents_nonexistent(self, plugin_manager):
        """Discovering from nonexistent dir returns 0."""
        count = plugin_manager.discover_agents("/nonexistent/path")
        assert count == 0


# ───────────── Bootstrap Tests ─────────────

class TestBootstrap:
    """Brain bootstrap and agent auto-registration tests."""

    @pytest.mark.asyncio
    async def test_bootstrap_all_agents(self, event_bus):
        """Bootstrap registers all built-in agents."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)
        brain.bootstrap_agents()

        assert "triage" in brain._agents
        assert "threat_hunter" in brain._agents
        assert "incident_responder" in brain._agents
        assert "compliance_auditor" in brain._agents
        assert "forensic_analyst" in brain._agents
        assert "vuln_scanner" in brain._agents
        assert "red_team" in brain._agents
        assert "purple_team" in brain._agents
        assert len(brain._agents) == 8

    @pytest.mark.asyncio
    async def test_bootstrap_disabled_agent(self, event_bus):
        """Disabled agents are skipped during bootstrap."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)
        brain.bootstrap_agents({"red_team": {"enabled": False}})

        assert "red_team" not in brain._agents
        assert "triage" in brain._agents  # Others still registered

    @pytest.mark.asyncio
    async def test_load_plugins_injects_techniques(self, event_bus):
        """Loading plugins injects custom techniques into red team."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain
        from src.agents.red_team_agent import TECHNIQUE_LIBRARY

        original_count = len(TECHNIQUE_LIBRARY)

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)
        brain.bootstrap_agents()

        # Add a technique pack to plugin manager
        brain.plugin_manager._technique_packs["test"] = {
            "T9999": {
                "name": "Plugin Test Technique",
                "tactic": "execution",
                "description": "From plugin",
                "platforms": ["windows"],
                "simulation_indicators": {},
                "detection_sources": [],
            },
        }

        brain.load_plugins({})

        assert "T9999" in TECHNIQUE_LIBRARY
        assert TECHNIQUE_LIBRARY["T9999"]["name"] == "Plugin Test Technique"

        # Cleanup
        TECHNIQUE_LIBRARY.pop("T9999", None)

    @pytest.mark.asyncio
    async def test_brain_has_plugin_manager(self, event_bus):
        """Brain initializes plugin manager."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)
        assert brain.plugin_manager is not None
        assert isinstance(brain.plugin_manager, PluginManager)

    @pytest.mark.asyncio
    async def test_status_includes_plugins(self, event_bus):
        """Status report includes plugin info."""
        from src.core.config import SentinelConfig
        from src.core.brain import SentinelBrain

        config = SentinelConfig()
        brain = SentinelBrain(config=config, event_bus=event_bus)
        status = brain.get_status()
        assert "plugins" in status
        assert "total_plugins_loaded" in status["plugins"]
