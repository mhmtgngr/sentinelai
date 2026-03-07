"""Plugin manager for Sentinel-AI — makes the platform fully extensible.

Supports loading custom agents, adapters, detection rules, playbooks,
red team techniques, and STRIDE templates from:
1. Python modules (drop-in .py files in designated directories)
2. YAML/JSON config files (techniques, sigma rules, playbooks, STRIDE templates)
3. Entry points or explicit registration via config

Usage:
    # Auto-discover from directories
    pm = PluginManager(event_bus, config)
    pm.discover_agents("plugins/agents/")
    pm.discover_adapters("plugins/adapters/")
    pm.load_technique_packs("config/techniques/")
    pm.load_stride_templates("config/stride/")

    # Register custom components programmatically
    pm.register_agent("my_agent", MyAgentClass)
    pm.register_adapter("my_vendor", MyAdapterClass)
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
from pathlib import Path
from typing import Any

import yaml

from src.agents.base_agent import BaseAgent
from src.core.event_bus import EventBus
from src.integrations.base_adapter import BaseSecurityAdapter

logger = logging.getLogger(__name__)


class PluginManager:
    """Central plugin manager for extending Sentinel-AI with custom components.

    Extension points:
    - Agents: custom BaseAgent subclasses (Python modules)
    - Adapters: custom BaseSecurityAdapter subclasses (Python modules)
    - Techniques: MITRE ATT&CK technique definitions (YAML)
    - Playbooks: SOAR playbook definitions (YAML) — loaded via PlaybookEngine
    - Sigma rules: detection rules (YAML) — loaded via SigmaEngine
    - STRIDE templates: threat model templates (YAML)
    - Hooks: event-driven callbacks for custom logic
    """

    def __init__(self, event_bus: EventBus, config: dict[str, Any] | None = None) -> None:
        self.event_bus = event_bus
        self.config = config or {}

        # Registered plugin classes (not yet instantiated)
        self._agent_classes: dict[str, type[BaseAgent]] = {}
        self._adapter_classes: dict[str, type[BaseSecurityAdapter]] = {}

        # Loaded extension data
        self._technique_packs: dict[str, dict[str, Any]] = {}
        self._stride_templates: dict[str, list[dict[str, Any]]] = {}
        self._hooks: dict[str, list[Any]] = {}  # event_name -> [callbacks]

        # Track loaded plugins
        self._loaded_plugins: list[dict[str, Any]] = []

    # ───────────── Agent Plugins ─────────────

    def register_agent(self, name: str, agent_class: type[BaseAgent]) -> None:
        """Register a custom agent class."""
        if not issubclass(agent_class, BaseAgent):
            raise TypeError(f"{agent_class} must be a subclass of BaseAgent")
        self._agent_classes[name] = agent_class
        self._loaded_plugins.append({
            "type": "agent",
            "name": name,
            "class": agent_class.__name__,
        })
        logger.info("Plugin registered: agent '%s' (%s)", name, agent_class.__name__)

    def create_agent(self, name: str, config: dict[str, Any] | None = None) -> BaseAgent:
        """Create an instance of a registered agent."""
        if name not in self._agent_classes:
            raise ValueError(f"Agent plugin not found: {name}. Available: {list(self._agent_classes.keys())}")
        return self._agent_classes[name](self.event_bus, config)

    def discover_agents(self, directory: str | Path) -> int:
        """Discover and register agent plugins from Python files in a directory.

        Each Python file should define a class that extends BaseAgent.
        The class must have a `name` attribute used as the registration key.
        """
        return self._discover_modules(directory, BaseAgent, self._agent_classes, "agent")

    # ───────────── Adapter Plugins ─────────────

    def register_adapter(self, vendor: str, adapter_class: type[BaseSecurityAdapter]) -> None:
        """Register a custom adapter class."""
        if not issubclass(adapter_class, BaseSecurityAdapter):
            raise TypeError(f"{adapter_class} must be a subclass of BaseSecurityAdapter")
        self._adapter_classes[vendor] = adapter_class
        self._loaded_plugins.append({
            "type": "adapter",
            "name": vendor,
            "class": adapter_class.__name__,
        })
        logger.info("Plugin registered: adapter '%s' (%s)", vendor, adapter_class.__name__)

    def create_adapter(self, vendor: str, config: dict[str, Any]) -> BaseSecurityAdapter:
        """Create an instance of a registered adapter."""
        if vendor not in self._adapter_classes:
            raise ValueError(f"Adapter plugin not found: {vendor}. Available: {list(self._adapter_classes.keys())}")
        return self._adapter_classes[vendor](config)

    def discover_adapters(self, directory: str | Path) -> int:
        """Discover and register adapter plugins from Python files in a directory."""
        return self._discover_modules(directory, BaseSecurityAdapter, self._adapter_classes, "adapter")

    # ───────────── Technique Packs ─────────────

    def load_technique_packs(self, directory: str | Path) -> int:
        """Load ATT&CK technique definitions from YAML files.

        Each YAML file defines techniques that get added to the Red Team agent's
        TECHNIQUE_LIBRARY. Format:

            techniques:
              T1234.001:
                name: "My Custom Technique"
                tactic: "execution"
                description: "Description here"
                platforms: [windows, linux]
                simulation_indicators:
                  event_type: "process_creation"
                  command_patterns: ["suspicious_cmd"]
                detection_sources: [defender_xdr, qradar]
        """
        directory = Path(directory)
        if not directory.exists():
            return 0

        loaded = 0
        for yaml_file in directory.glob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if not data or "techniques" not in data:
                    continue

                pack_name = data.get("name", yaml_file.stem)
                techniques = data["techniques"]
                self._technique_packs[pack_name] = techniques
                loaded += len(techniques)

                self._loaded_plugins.append({
                    "type": "technique_pack",
                    "name": pack_name,
                    "techniques": len(techniques),
                    "file": str(yaml_file),
                })
                logger.info("Loaded technique pack: %s (%d techniques)", pack_name, len(techniques))
            except Exception:
                logger.exception("Failed to load technique pack: %s", yaml_file)

        return loaded

    def get_all_techniques(self) -> dict[str, dict[str, Any]]:
        """Get all loaded technique definitions (built-in + plugins)."""
        all_techniques: dict[str, dict[str, Any]] = {}

        # Load built-in techniques
        try:
            from src.agents.red_team_agent import TECHNIQUE_LIBRARY
            all_techniques.update(TECHNIQUE_LIBRARY)
        except ImportError:
            pass

        # Add plugin techniques
        for pack in self._technique_packs.values():
            all_techniques.update(pack)

        return all_techniques

    # ───────────── STRIDE Templates ─────────────

    def load_stride_templates(self, directory: str | Path) -> int:
        """Load custom STRIDE threat templates from YAML files.

        Format:
            asset_type: "database"
            threats:
              - category: "information_disclosure"
                title: "Database Data Breach"
                description: "..."
                likelihood: 4
                impact: 5
                mitre_techniques: [T1213]
                mitigations: ["Encrypt at rest", "Access controls"]
        """
        directory = Path(directory)
        if not directory.exists():
            return 0

        loaded = 0
        for yaml_file in directory.glob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if not data:
                    continue

                asset_type = data.get("asset_type", yaml_file.stem)
                threats = data.get("threats", [])
                self._stride_templates[asset_type] = threats
                loaded += len(threats)

                self._loaded_plugins.append({
                    "type": "stride_template",
                    "name": asset_type,
                    "threats": len(threats),
                    "file": str(yaml_file),
                })
                logger.info("Loaded STRIDE templates for %s (%d threats)", asset_type, len(threats))
            except Exception:
                logger.exception("Failed to load STRIDE template: %s", yaml_file)

        return loaded

    def get_all_stride_templates(self) -> dict[str, list[dict[str, Any]]]:
        """Get all STRIDE templates (built-in + plugins)."""
        from src.core.threat_modeling import STRIDE_TEMPLATES
        all_templates = dict(STRIDE_TEMPLATES)
        all_templates.update(self._stride_templates)
        return all_templates

    # ───────────── Event Hooks ─────────────

    def register_hook(self, event_name: str, callback: Any) -> None:
        """Register a callback hook for a specific event.

        Hooks let plugins react to system events without modifying core code.
        Example: register_hook("threat.detected", my_custom_handler)
        """
        if event_name not in self._hooks:
            self._hooks[event_name] = []
        self._hooks[event_name].append(callback)
        logger.info("Hook registered for event: %s", event_name)

    def get_hooks(self, event_name: str) -> list[Any]:
        """Get all hooks for an event."""
        return self._hooks.get(event_name, [])

    # ───────────── Plugin Lifecycle ─────────────

    def load_all(self, plugins_config: dict[str, Any] | None = None) -> dict[str, int]:
        """Load all plugins from configuration.

        Config format (config/plugins.yaml):
            plugins:
              agent_dirs: ["plugins/agents"]
              adapter_dirs: ["plugins/adapters"]
              technique_packs: ["config/techniques"]
              stride_templates: ["config/stride"]
              playbook_dirs: ["config/playbooks"]
              sigma_dirs: ["config/sigma_rules"]
        """
        cfg = plugins_config or self.config
        results = {
            "agents": 0,
            "adapters": 0,
            "techniques": 0,
            "stride_templates": 0,
        }

        for d in cfg.get("agent_dirs", []):
            results["agents"] += self.discover_agents(d)
        for d in cfg.get("adapter_dirs", []):
            results["adapters"] += self.discover_adapters(d)
        for d in cfg.get("technique_packs", []):
            results["techniques"] += self.load_technique_packs(d)
        for d in cfg.get("stride_templates", []):
            results["stride_templates"] += self.load_stride_templates(d)

        logger.info(
            "Plugin loading complete: %d agents, %d adapters, %d techniques, %d STRIDE templates",
            results["agents"], results["adapters"], results["techniques"], results["stride_templates"],
        )
        return results

    def get_loaded_plugins(self) -> list[dict[str, Any]]:
        """Get list of all loaded plugins."""
        return list(self._loaded_plugins)

    def get_stats(self) -> dict[str, Any]:
        """Get plugin manager statistics."""
        return {
            "agent_plugins": len(self._agent_classes),
            "adapter_plugins": len(self._adapter_classes),
            "technique_packs": len(self._technique_packs),
            "total_custom_techniques": sum(len(p) for p in self._technique_packs.values()),
            "stride_templates": len(self._stride_templates),
            "hooks": {name: len(cbs) for name, cbs in self._hooks.items()},
            "total_plugins_loaded": len(self._loaded_plugins),
        }

    # ───────────── Internal Discovery ─────────────

    def _discover_modules(
        self,
        directory: str | Path,
        base_class: type,
        registry: dict[str, Any],
        plugin_type: str,
    ) -> int:
        """Discover Python modules containing subclasses of base_class."""
        directory = Path(directory)
        if not directory.exists():
            logger.debug("Plugin directory not found: %s", directory)
            return 0

        discovered = 0
        for py_file in directory.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                module_name = f"plugin_{plugin_type}_{py_file.stem}"
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find all subclasses of base_class in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, base_class)
                        and attr is not base_class
                    ):
                        name = getattr(attr, "name", None) or getattr(attr, "vendor", None) or attr_name.lower()
                        registry[name] = attr
                        discovered += 1
                        self._loaded_plugins.append({
                            "type": plugin_type,
                            "name": name,
                            "class": attr.__name__,
                            "file": str(py_file),
                        })
                        logger.info("Discovered %s plugin: %s from %s", plugin_type, name, py_file.name)
            except Exception:
                logger.exception("Failed to load plugin module: %s", py_file)

        return discovered
