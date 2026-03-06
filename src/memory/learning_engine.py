"""Self-learning feedback loops for continuous improvement."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


class FeedbackVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    NEEDS_TUNING = "needs_tuning"


@dataclass
class FeedbackEntry:
    alert_id: str
    verdict: FeedbackVerdict
    analyst_notes: str = ""
    rule_id: str = ""
    attack_type: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class LearningEngine:
    """Tracks analyst feedback to improve detection accuracy over time."""

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._feedback_history: list[FeedbackEntry] = []
        self._rule_accuracy: dict[str, dict[str, int]] = {}  # rule_id -> {tp, fp, total}
        self._false_positive_patterns: list[str] = []
        self._confidence_adjustments: dict[str, float] = {}  # rule_id -> adjustment factor

    async def record_feedback(self, feedback: FeedbackEntry) -> None:
        """Record analyst feedback and update learning models."""
        self._feedback_history.append(feedback)

        # Update rule accuracy tracking
        rule_id = feedback.rule_id
        if rule_id:
            if rule_id not in self._rule_accuracy:
                self._rule_accuracy[rule_id] = {"tp": 0, "fp": 0, "total": 0}
            self._rule_accuracy[rule_id]["total"] += 1
            if feedback.verdict == FeedbackVerdict.TRUE_POSITIVE:
                self._rule_accuracy[rule_id]["tp"] += 1
            elif feedback.verdict == FeedbackVerdict.FALSE_POSITIVE:
                self._rule_accuracy[rule_id]["fp"] += 1
                if feedback.analyst_notes:
                    self._false_positive_patterns.append(feedback.analyst_notes)

        # Recalculate confidence adjustments
        self._recalculate_confidence(rule_id)

        await self.event_bus.publish(Event(
            event_type=EventType.FEEDBACK_RECEIVED,
            data={
                "alert_id": feedback.alert_id,
                "verdict": feedback.verdict.value,
                "rule_id": rule_id,
            },
            source="learning_engine",
        ))

    def get_confidence_adjustment(self, rule_id: str) -> float:
        """Get the confidence adjustment factor for a rule. 1.0 = no change, <1 = reduce, >1 = boost."""
        return self._confidence_adjustments.get(rule_id, 1.0)

    def get_false_positive_patterns(self) -> list[str]:
        """Get accumulated false positive patterns for triage agent."""
        return self._false_positive_patterns.copy()

    def get_rule_accuracy(self, rule_id: str) -> dict[str, Any]:
        """Get accuracy statistics for a specific rule."""
        stats = self._rule_accuracy.get(rule_id, {"tp": 0, "fp": 0, "total": 0})
        total = stats["total"]
        if total == 0:
            return {**stats, "precision": 0.0, "fp_rate": 0.0}
        return {
            **stats,
            "precision": stats["tp"] / total,
            "fp_rate": stats["fp"] / total,
        }

    def get_overall_stats(self) -> dict[str, Any]:
        """Get overall learning engine statistics."""
        total_feedback = len(self._feedback_history)
        tp = sum(1 for f in self._feedback_history if f.verdict == FeedbackVerdict.TRUE_POSITIVE)
        fp = sum(1 for f in self._feedback_history if f.verdict == FeedbackVerdict.FALSE_POSITIVE)

        rules_needing_tuning = [
            rule_id for rule_id, stats in self._rule_accuracy.items()
            if stats["total"] > 5 and stats["fp"] / stats["total"] > 0.5
        ]

        return {
            "total_feedback": total_feedback,
            "true_positives": tp,
            "false_positives": fp,
            "overall_precision": tp / total_feedback if total_feedback > 0 else 0,
            "rules_tracked": len(self._rule_accuracy),
            "rules_needing_tuning": rules_needing_tuning,
            "fp_patterns_learned": len(self._false_positive_patterns),
        }

    def _recalculate_confidence(self, rule_id: str) -> None:
        """Recalculate confidence adjustment for a rule based on feedback history."""
        if not rule_id or rule_id not in self._rule_accuracy:
            return
        stats = self._rule_accuracy[rule_id]
        total = stats["total"]
        if total < 3:
            return  # Not enough data

        precision = stats["tp"] / total
        fp_rate = stats["fp"] / total

        # High FP rate -> reduce confidence, high precision -> boost
        if fp_rate > 0.7:
            self._confidence_adjustments[rule_id] = 0.3
        elif fp_rate > 0.5:
            self._confidence_adjustments[rule_id] = 0.6
        elif precision > 0.9:
            self._confidence_adjustments[rule_id] = 1.2
        else:
            self._confidence_adjustments[rule_id] = 1.0
