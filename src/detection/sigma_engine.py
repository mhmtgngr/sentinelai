"""Sigma rule engine for detection rule matching."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str = ""
    status: str = "experimental"
    level: str = "medium"
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)


@dataclass
class SigmaMatch:
    rule: SigmaRule
    matched_fields: dict[str, Any] = field(default_factory=dict)


class SigmaEngine:
    """Loads and evaluates Sigma detection rules against security events."""

    def __init__(self) -> None:
        self._rules: list[SigmaRule] = []

    def load_rules(self, rules_dir: str | Path) -> int:
        """Load Sigma rules from a directory of YAML files."""
        rules_dir = Path(rules_dir)
        count = 0
        if not rules_dir.exists():
            logger.warning("Sigma rules directory does not exist: %s", rules_dir)
            return 0

        for rule_file in rules_dir.glob("**/*.yml"):
            try:
                with open(rule_file) as f:
                    data = yaml.safe_load(f)
                if not data:
                    continue
                rule = SigmaRule(
                    rule_id=data.get("id", rule_file.stem),
                    title=data.get("title", ""),
                    description=data.get("description", ""),
                    status=data.get("status", "experimental"),
                    level=data.get("level", "medium"),
                    logsource=data.get("logsource", {}),
                    detection=data.get("detection", {}),
                    tags=data.get("tags", []),
                    falsepositives=data.get("falsepositives", []),
                )
                self._rules.append(rule)
                count += 1
            except Exception:
                logger.exception("Error loading Sigma rule: %s", rule_file)
        logger.info("Loaded %d Sigma rules from %s", count, rules_dir)
        return count

    def add_rule(self, rule: SigmaRule) -> None:
        self._rules.append(rule)

    def evaluate(self, event: dict[str, Any]) -> list[SigmaMatch]:
        """Evaluate an event against all loaded Sigma rules."""
        matches = []
        for rule in self._rules:
            matched_fields = self._match_rule(rule, event)
            if matched_fields is not None:
                matches.append(SigmaMatch(rule=rule, matched_fields=matched_fields))
        return matches

    def _match_rule(self, rule: SigmaRule, event: dict[str, Any]) -> dict[str, Any] | None:
        """Check if an event matches a single Sigma rule's detection logic."""
        detection = rule.detection
        if not detection:
            return None

        condition = detection.get("condition", "")
        matched_fields: dict[str, Any] = {}

        # Process each selection in the detection block
        selections_matched: dict[str, bool] = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                selections_matched[key] = self._match_selection(value, event, matched_fields)
            elif isinstance(value, list):
                # List of dicts (OR)
                selections_matched[key] = any(
                    self._match_selection(item, event, matched_fields)
                    for item in value if isinstance(item, dict)
                )

        # Evaluate condition
        if not condition:
            # Default: all selections must match
            if all(selections_matched.values()):
                return matched_fields
            return None

        result = self._evaluate_condition(condition, selections_matched)
        return matched_fields if result else None

    def _match_selection(self, selection: dict[str, Any], event: dict[str, Any], matched_fields: dict[str, Any]) -> bool:
        """Match a selection dict against an event."""
        for sel_field, sel_value in selection.items():
            # Handle Sigma field modifiers
            field_name = sel_field
            modifier = ""
            if "|" in sel_field:
                parts = sel_field.split("|")
                field_name = parts[0]
                modifier = parts[1] if len(parts) > 1 else ""

            event_value = event.get(field_name, "")
            if isinstance(event_value, str):
                event_value_lower = event_value.lower()
            else:
                event_value_lower = str(event_value).lower()

            if isinstance(sel_value, list):
                # Any value in list matches
                match = any(
                    self._field_match(str(v).lower(), event_value_lower, modifier)
                    for v in sel_value
                )
            else:
                match = self._field_match(str(sel_value).lower(), event_value_lower, modifier)

            if not match:
                return False
            matched_fields[field_name] = event_value

        return True

    @staticmethod
    def _field_match(pattern: str, value: str, modifier: str) -> bool:
        """Match a single field value with optional modifiers."""
        if modifier == "contains":
            return pattern in value
        if modifier == "startswith":
            return value.startswith(pattern)
        if modifier == "endswith":
            return value.endswith(pattern)
        if modifier == "re":
            import re
            try:
                return bool(re.search(pattern, value))
            except re.error:
                return False

        # Default: exact match or wildcard
        if "*" in pattern:
            import fnmatch
            return fnmatch.fnmatch(value, pattern)
        return pattern == value

    @staticmethod
    def _evaluate_condition(condition: str, selections: dict[str, bool]) -> bool:
        """Evaluate a Sigma condition string against matched selections."""
        # Simple condition evaluation
        expr = condition.strip()

        # Handle "selection" (single)
        if expr in selections:
            return selections[expr]

        # Handle "all of selection*"
        if expr.startswith("all of "):
            pattern = expr[7:].replace("*", "")
            matching = [v for k, v in selections.items() if k.startswith(pattern)]
            return all(matching) if matching else False

        # Handle "1 of selection*"
        if expr.startswith("1 of "):
            pattern = expr[5:].replace("*", "")
            matching = [v for k, v in selections.items() if k.startswith(pattern)]
            return any(matching)

        # Handle "selection1 and selection2"
        if " and " in expr:
            parts = [p.strip() for p in expr.split(" and ")]
            return all(selections.get(p, False) for p in parts)

        # Handle "selection1 or selection2"
        if " or " in expr:
            parts = [p.strip() for p in expr.split(" or ")]
            return any(selections.get(p, False) for p in parts)

        # Handle "not selection"
        if expr.startswith("not "):
            inner = expr[4:].strip()
            return not selections.get(inner, False)

        return False

    def get_stats(self) -> dict[str, Any]:
        levels: dict[str, int] = {}
        for rule in self._rules:
            levels[rule.level] = levels.get(rule.level, 0) + 1
        return {
            "total_rules": len(self._rules),
            "by_level": levels,
        }
