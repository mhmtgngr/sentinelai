"""SOAR playbook engine for Sentinel-AI.

Loads YAML-based playbooks, evaluates triggers against events,
executes playbook steps sequentially, and routes destructive
actions through the autonomous decision engine.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


@dataclass
class PlaybookStep:
    name: str = ""
    action: str = ""
    adapter_type: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    conditions: dict[str, Any] = field(default_factory=dict)
    on_failure: str = "continue"  # continue, abort, skip


@dataclass
class Playbook:
    name: str = ""
    description: str = ""
    trigger: dict[str, Any] = field(default_factory=dict)
    steps: list[PlaybookStep] = field(default_factory=list)
    enabled: bool = True
    priority: int = 50  # Lower = higher priority


@dataclass
class StepResult:
    step_name: str = ""
    action: str = ""
    success: bool = False
    output: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    duration_ms: float = 0


@dataclass
class PlaybookExecution:
    execution_id: str = field(default_factory=lambda: str(uuid4()))
    playbook_name: str = ""
    status: str = "running"  # running, completed, failed, aborted
    trigger_data: dict[str, Any] = field(default_factory=dict)
    step_results: list[StepResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None


class PlaybookEngine:
    """SOAR playbook engine with YAML-based playbook definitions."""

    # Template variable pattern: {{ variable_name }}
    _template_re = re.compile(r"\{\{\s*(\w+(?:\.\w+)*)\s*\}\}")

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._playbooks: dict[str, Playbook] = {}
        self._executions: list[PlaybookExecution] = []
        self._action_handlers: dict[str, Any] = {}  # action -> callable
        self._max_executions = 1000

    def load_playbooks(self, config_dir: str | Path) -> int:
        """Load all YAML playbooks from a directory."""
        config_path = Path(config_dir)
        loaded = 0

        if not config_path.exists():
            logger.warning("Playbook directory not found: %s", config_dir)
            return 0

        for yaml_file in config_path.glob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if not data:
                    continue

                playbook = self._parse_playbook(data)
                self._playbooks[playbook.name] = playbook
                loaded += 1
                logger.info("Loaded playbook: %s (%d steps)", playbook.name, len(playbook.steps))
            except Exception:
                logger.exception("Failed to load playbook: %s", yaml_file)

        return loaded

    def add_playbook(self, playbook: Playbook) -> None:
        self._playbooks[playbook.name] = playbook

    def register_action(self, action_name: str, handler: Any) -> None:
        """Register an action handler (callable) for playbook steps."""
        self._action_handlers[action_name] = handler

    def evaluate_trigger(self, playbook: Playbook, event_data: dict[str, Any]) -> bool:
        """Check if an event matches a playbook's trigger conditions."""
        trigger = playbook.trigger
        if not trigger:
            return False

        conditions = trigger.get("conditions", {})
        for key, expected in conditions.items():
            actual = event_data.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        # Check event type trigger
        event_type = trigger.get("event_type", "")
        if event_type:
            actual_type = event_data.get("event_type", "")
            if actual_type and actual_type != event_type:
                return False

        return True

    def find_matching_playbooks(self, event_data: dict[str, Any]) -> list[Playbook]:
        """Find all playbooks whose triggers match the given event."""
        matches = []
        for playbook in self._playbooks.values():
            if playbook.enabled and self.evaluate_trigger(playbook, event_data):
                matches.append(playbook)
        return sorted(matches, key=lambda p: p.priority)

    async def execute_playbook(
        self,
        playbook_name: str,
        trigger_data: dict[str, Any],
    ) -> PlaybookExecution:
        """Execute a playbook with the given trigger data."""
        playbook = self._playbooks.get(playbook_name)
        if not playbook:
            return PlaybookExecution(
                playbook_name=playbook_name,
                status="failed",
                trigger_data=trigger_data,
                step_results=[StepResult(step_name="lookup", error=f"Playbook not found: {playbook_name}")],
            )

        execution = PlaybookExecution(
            playbook_name=playbook_name,
            trigger_data=trigger_data,
        )

        for step in playbook.steps:
            # Check step conditions
            if step.conditions and not self._evaluate_conditions(step.conditions, trigger_data):
                execution.step_results.append(StepResult(
                    step_name=step.name,
                    action=step.action,
                    success=True,
                    output={"skipped": "conditions not met"},
                ))
                continue

            # Resolve template variables in params
            resolved_params = self._resolve_templates(step.params, trigger_data)

            # Execute the step
            start = datetime.now(timezone.utc)
            step_result = await self._execute_step(step, resolved_params, trigger_data)
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            step_result.duration_ms = elapsed
            execution.step_results.append(step_result)

            # Handle failure
            if not step_result.success:
                if step.on_failure == "abort":
                    execution.status = "aborted"
                    break
                elif step.on_failure == "skip":
                    continue
                # default "continue" — keep going

        if execution.status == "running":
            execution.status = "completed"
        execution.completed_at = datetime.now(timezone.utc)

        # Store execution
        self._executions.append(execution)
        if len(self._executions) > self._max_executions:
            self._executions = self._executions[-self._max_executions:]

        # Publish event
        await self.event_bus.publish(Event(
            event_type=EventType.PLAYBOOK_EXECUTED,
            data={
                "execution_id": execution.execution_id,
                "playbook": playbook_name,
                "status": execution.status,
                "steps_executed": len(execution.step_results),
                "steps_succeeded": sum(1 for s in execution.step_results if s.success),
            },
            source="playbook_engine",
        ))

        return execution

    def get_execution_history(
        self,
        playbook_name: str | None = None,
        limit: int = 50,
    ) -> list[PlaybookExecution]:
        execs = self._executions
        if playbook_name:
            execs = [e for e in execs if e.playbook_name == playbook_name]
        return execs[-limit:]

    def get_playbooks(self) -> list[dict[str, Any]]:
        return [
            {
                "name": p.name,
                "description": p.description,
                "steps": len(p.steps),
                "enabled": p.enabled,
                "trigger": p.trigger,
            }
            for p in self._playbooks.values()
        ]

    def get_stats(self) -> dict[str, Any]:
        total = len(self._executions)
        completed = sum(1 for e in self._executions if e.status == "completed")
        failed = sum(1 for e in self._executions if e.status == "failed")
        return {
            "playbooks_loaded": len(self._playbooks),
            "total_executions": total,
            "completed": completed,
            "failed": failed,
            "success_rate": round(completed / max(total, 1), 3),
        }

    async def _execute_step(
        self,
        step: PlaybookStep,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> StepResult:
        """Execute a single playbook step."""
        handler = self._action_handlers.get(step.action)
        if not handler:
            return StepResult(
                step_name=step.name,
                action=step.action,
                success=False,
                error=f"No handler registered for action: {step.action}",
            )

        try:
            if callable(handler):
                result = await handler(params=params, context=context)
                return StepResult(
                    step_name=step.name,
                    action=step.action,
                    success=True,
                    output=result if isinstance(result, dict) else {"result": result},
                )
        except Exception as exc:
            return StepResult(
                step_name=step.name,
                action=step.action,
                success=False,
                error=str(exc),
            )

        return StepResult(step_name=step.name, action=step.action, success=False, error="Handler not callable")

    def _resolve_templates(self, params: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
        """Resolve {{ variable }} templates in parameter values."""
        resolved: dict[str, Any] = {}
        for key, value in params.items():
            if isinstance(value, str):
                resolved[key] = self._template_re.sub(
                    lambda m: str(self._get_nested(data, m.group(1), m.group(0))),
                    value,
                )
            elif isinstance(value, dict):
                resolved[key] = self._resolve_templates(value, data)
            else:
                resolved[key] = value
        return resolved

    @staticmethod
    def _get_nested(data: dict[str, Any], key_path: str, default: Any = "") -> Any:
        """Get a nested value from a dict using dot notation."""
        keys = key_path.split(".")
        current: Any = data
        for k in keys:
            if isinstance(current, dict):
                current = current.get(k)
            else:
                return default
            if current is None:
                return default
        return current

    @staticmethod
    def _evaluate_conditions(conditions: dict[str, Any], data: dict[str, Any]) -> bool:
        """Evaluate step conditions against event data."""
        for key, expected in conditions.items():
            actual = data.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    @staticmethod
    def _parse_playbook(data: dict[str, Any]) -> Playbook:
        """Parse a playbook from a YAML dict."""
        steps = []
        for step_data in data.get("steps", []):
            steps.append(PlaybookStep(
                name=step_data.get("name", ""),
                action=step_data.get("action", ""),
                adapter_type=step_data.get("adapter_type", ""),
                params=step_data.get("params", {}),
                conditions=step_data.get("conditions", {}),
                on_failure=step_data.get("on_failure", "continue"),
            ))

        return Playbook(
            name=data.get("name", ""),
            description=data.get("description", ""),
            trigger=data.get("trigger", {}),
            steps=steps,
            enabled=data.get("enabled", True),
            priority=data.get("priority", 50),
        )
