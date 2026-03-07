"""Self-learning system that continuously improves from outcomes and human guidance."""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.core.autonomous import Decision, DecisionOutcome
from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


@dataclass
class LearningSnapshot:
    """Point-in-time snapshot of learning metrics for trend tracking."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_decisions: int = 0
    autonomous_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    mean_confidence: float = 0.0
    escalation_rate: float = 0.0
    human_override_rate: float = 0.0


@dataclass
class ActionProfile:
    """Learned profile for a specific action type."""
    action: str = ""
    total_executions: int = 0
    success_count: int = 0
    failure_count: int = 0
    false_positive_count: int = 0
    overreaction_count: int = 0
    avg_confidence_at_success: float = 0.0
    avg_confidence_at_failure: float = 0.0
    human_override_count: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def accuracy(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.success_count / self.total_executions

    @property
    def optimal_confidence_threshold(self) -> float:
        """Calculate optimal confidence threshold based on outcomes."""
        if self.total_executions < 10:
            return 0.85  # Default — not enough data
        # If we have high accuracy, we can lower the threshold
        # If we have many failures, raise it
        base = 0.85
        accuracy_adj = (self.accuracy - 0.8) * 0.5  # +-0.1 based on accuracy
        fp_adj = -(self.false_positive_count / max(self.total_executions, 1)) * 0.3
        return max(0.5, min(0.98, base + accuracy_adj + fp_adj))


@dataclass
class ThreatPattern:
    """A learned threat pattern from observed incidents."""
    pattern_id: str = ""
    attack_type: str = ""
    indicators: list[str] = field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.5
    times_seen: int = 0
    times_confirmed: int = 0
    recommended_actions: list[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SelfLearningSystem:
    """Learns from every decision, outcome, and human interaction to improve autonomy.

    Learning happens at multiple levels:
    1. Action level: Which actions work for which scenarios
    2. Confidence calibration: Adjusting thresholds based on accuracy
    3. Pattern recognition: Learning new threat patterns from incidents
    4. Human guidance integration: Learning from approvals/denials
    5. False positive reduction: Learning what to ignore
    """

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._action_profiles: dict[str, ActionProfile] = {}
        self._threat_patterns: list[ThreatPattern] = []
        self._false_positive_signatures: list[dict[str, Any]] = []
        self._learning_snapshots: list[LearningSnapshot] = []
        self._human_guidance_log: list[dict[str, Any]] = []
        self._all_decisions: list[Decision] = []
        self._concept_drift_window: list[float] = []  # Recent accuracy values

        # Subscribe to learning events
        self.event_bus.subscribe(EventType.FEEDBACK_RECEIVED, self._on_feedback)
        self.event_bus.subscribe(EventType.ACTION_APPROVED, self._on_action_approved)

    async def learn_from_decision(self, decision: Decision) -> dict[str, Any]:
        """Process a completed decision and extract learning."""
        self._all_decisions.append(decision)
        insights: dict[str, Any] = {"adjustments": []}

        # Update action profile
        profile = self._get_or_create_profile(decision.action)
        profile.total_executions += 1

        if decision.outcome == DecisionOutcome.SUCCESS:
            profile.success_count += 1
            profile.avg_confidence_at_success = self._running_avg(
                profile.avg_confidence_at_success, decision.confidence, profile.success_count
            )
        elif decision.outcome == DecisionOutcome.FAILURE:
            profile.failure_count += 1
            profile.avg_confidence_at_failure = self._running_avg(
                profile.avg_confidence_at_failure, decision.confidence, profile.failure_count
            )
        elif decision.outcome == DecisionOutcome.FALSE_POSITIVE:
            profile.false_positive_count += 1
            # Learn the false positive signature
            self._learn_false_positive(decision)
            insights["adjustments"].append({
                "type": "false_positive_learned",
                "action": decision.action,
                "target": decision.target,
            })
        elif decision.outcome == DecisionOutcome.OVERREACTION:
            profile.overreaction_count += 1
            insights["adjustments"].append({
                "type": "overreaction_noted",
                "action": decision.action,
                "new_threshold": profile.optimal_confidence_threshold,
            })

        if decision.approved_by and decision.approved_by != "autonomous":
            profile.human_override_count += 1

        profile.last_updated = datetime.now(timezone.utc)

        # Check for concept drift
        drift = self._check_concept_drift()
        if drift:
            insights["concept_drift"] = drift

        # Learn threat pattern if applicable
        if decision.outcome == DecisionOutcome.SUCCESS and decision.evidence:
            self._learn_threat_pattern(decision)

        await self.event_bus.publish(Event(
            event_type=EventType.MODEL_UPDATED,
            data={
                "action": decision.action,
                "new_accuracy": profile.accuracy,
                "new_threshold": profile.optimal_confidence_threshold,
                "insights": insights,
            },
            source="self_learning",
        ))

        return insights

    def get_recommended_actions(self, attack_type: str, severity: str) -> list[dict[str, Any]]:
        """Get recommended actions based on learned patterns."""
        recommendations = []

        # Find matching threat patterns
        matching = [p for p in self._threat_patterns if p.attack_type == attack_type]
        for pattern in sorted(matching, key=lambda p: p.confidence, reverse=True):
            for action in pattern.recommended_actions:
                profile = self._action_profiles.get(action)
                if profile and profile.accuracy > 0.6:
                    recommendations.append({
                        "action": action,
                        "confidence": round(pattern.confidence * profile.accuracy, 3),
                        "based_on": f"Pattern seen {pattern.times_seen}x, action accuracy {profile.accuracy:.0%}",
                    })

        # Fall back to action profiles
        if not recommendations:
            for action, profile in self._action_profiles.items():
                if profile.accuracy > 0.7 and profile.total_executions > 5:
                    recommendations.append({
                        "action": action,
                        "confidence": round(profile.accuracy * 0.7, 3),
                        "based_on": f"General accuracy {profile.accuracy:.0%} over {profile.total_executions} executions",
                    })

        return sorted(recommendations, key=lambda r: r["confidence"], reverse=True)[:5]

    def is_known_false_positive(self, event_data: dict[str, Any]) -> float:
        """Check if an event matches a learned false positive signature. Returns 0-1 match score."""
        if not self._false_positive_signatures:
            return 0.0

        best_match = 0.0
        for sig in self._false_positive_signatures:
            match_score = self._compute_fp_match(sig, event_data)
            best_match = max(best_match, match_score)

        return best_match

    def get_confidence_threshold(self, action: str) -> float:
        """Get the learned optimal confidence threshold for an action."""
        profile = self._action_profiles.get(action)
        if profile and profile.total_executions >= 10:
            return profile.optimal_confidence_threshold
        return 0.85  # Default

    def take_snapshot(self) -> LearningSnapshot:
        """Take a point-in-time learning snapshot for trend analysis."""
        total = len(self._all_decisions)
        resolved = [d for d in self._all_decisions if d.outcome != DecisionOutcome.PENDING]
        auto = [d for d in resolved if d.approved_by == "autonomous"]
        auto_correct = [d for d in auto if d.outcome == DecisionOutcome.SUCCESS]
        escalated = [d for d in self._all_decisions if d.requires_approval]
        human_overrides = [d for d in resolved if d.approved_by and d.approved_by != "autonomous" and not d.approved]

        snapshot = LearningSnapshot(
            total_decisions=total,
            autonomous_accuracy=len(auto_correct) / max(len(auto), 1),
            false_positive_rate=sum(
                1 for d in resolved if d.outcome == DecisionOutcome.FALSE_POSITIVE
            ) / max(len(resolved), 1),
            mean_confidence=sum(d.confidence for d in resolved) / max(len(resolved), 1),
            escalation_rate=len(escalated) / max(total, 1),
            human_override_rate=len(human_overrides) / max(len(resolved), 1),
        )
        self._learning_snapshots.append(snapshot)
        return snapshot

    def get_learning_report(self) -> dict[str, Any]:
        """Comprehensive learning status report."""
        snapshot = self.take_snapshot()

        # Calculate improvement trend
        trend = "stable"
        if len(self._learning_snapshots) >= 5:
            recent = self._learning_snapshots[-5:]
            acc_values = [s.autonomous_accuracy for s in recent]
            if acc_values[-1] > acc_values[0] + 0.05:
                trend = "improving"
            elif acc_values[-1] < acc_values[0] - 0.05:
                trend = "degrading"

        profiles = {}
        for action, profile in self._action_profiles.items():
            profiles[action] = {
                "total": profile.total_executions,
                "accuracy": round(profile.accuracy, 3),
                "optimal_threshold": round(profile.optimal_confidence_threshold, 3),
                "fp_rate": round(profile.false_positive_count / max(profile.total_executions, 1), 3),
                "human_overrides": profile.human_override_count,
            }

        return {
            "current_snapshot": {
                "autonomous_accuracy": round(snapshot.autonomous_accuracy, 3),
                "false_positive_rate": round(snapshot.false_positive_rate, 3),
                "escalation_rate": round(snapshot.escalation_rate, 3),
                "mean_confidence": round(snapshot.mean_confidence, 3),
                "human_override_rate": round(snapshot.human_override_rate, 3),
            },
            "trend": trend,
            "action_profiles": profiles,
            "threat_patterns_learned": len(self._threat_patterns),
            "fp_signatures_learned": len(self._false_positive_signatures),
            "total_human_guidance": len(self._human_guidance_log),
            "concept_drift_detected": len(self._concept_drift_window) > 20
                and self._concept_drift_window[-1] < 0.6,
        }

    # ---- Internal learning methods ----

    def _get_or_create_profile(self, action: str) -> ActionProfile:
        if action not in self._action_profiles:
            self._action_profiles[action] = ActionProfile(action=action)
        return self._action_profiles[action]

    def _learn_false_positive(self, decision: Decision) -> None:
        """Learn a false positive signature from a decision outcome."""
        signature = {
            "action": decision.action,
            "target": decision.target,
            "evidence_keys": [list(e.keys()) for e in decision.evidence[:3]],
            "reasoning_keywords": self._extract_keywords(decision.reasoning),
            "learned_at": datetime.now(timezone.utc).isoformat(),
        }
        self._false_positive_signatures.append(signature)
        logger.info("Learned FP signature: %s on %s", decision.action, decision.target)

    def _learn_threat_pattern(self, decision: Decision) -> None:
        """Learn or reinforce a threat pattern from a successful detection."""
        indicators = []
        for e in decision.evidence:
            for key in ("source_ip", "domain", "hostname", "user", "process_name"):
                if key in e:
                    indicators.append(f"{key}={e[key]}")

        # Check if pattern already exists
        for pattern in self._threat_patterns:
            overlap = set(indicators) & set(pattern.indicators)
            if len(overlap) >= 2:
                pattern.times_seen += 1
                pattern.times_confirmed += 1
                pattern.confidence = min(0.99, pattern.confidence + 0.05)
                pattern.last_seen = datetime.now(timezone.utc)
                if decision.action not in pattern.recommended_actions:
                    pattern.recommended_actions.append(decision.action)
                return

        # New pattern
        attack_type = ""
        for r in decision.reasoning:
            for at in ("brute_force", "malware", "lateral_movement", "data_exfiltration",
                       "phishing", "privilege_escalation", "reconnaissance"):
                if at in r.lower():
                    attack_type = at
                    break
            if attack_type:
                break

        self._threat_patterns.append(ThreatPattern(
            pattern_id=decision.decision_id,
            attack_type=attack_type or "unknown",
            indicators=indicators,
            severity=decision.severity,
            confidence=decision.confidence * 0.8,
            times_seen=1,
            times_confirmed=1,
            recommended_actions=[decision.action],
        ))

    def _check_concept_drift(self) -> dict[str, Any] | None:
        """Detect if the environment has shifted (detection accuracy dropping)."""
        recent = self._all_decisions[-50:]
        if len(recent) < 20:
            return None

        resolved = [d for d in recent if d.outcome != DecisionOutcome.PENDING]
        if not resolved:
            return None

        accuracy = sum(1 for d in resolved if d.outcome == DecisionOutcome.SUCCESS) / len(resolved)
        self._concept_drift_window.append(accuracy)

        if len(self._concept_drift_window) < 10:
            return None

        recent_avg = sum(self._concept_drift_window[-5:]) / 5
        historical_avg = sum(self._concept_drift_window[:-5]) / max(len(self._concept_drift_window) - 5, 1)

        if recent_avg < historical_avg - 0.15:
            return {
                "detected": True,
                "recent_accuracy": round(recent_avg, 3),
                "historical_accuracy": round(historical_avg, 3),
                "drift_magnitude": round(historical_avg - recent_avg, 3),
                "recommendation": "Consider retraining models or reviewing detection rules",
            }
        return None

    @staticmethod
    def _compute_fp_match(signature: dict, event_data: dict) -> float:
        """Compute how well an event matches a false positive signature."""
        score = 0.0
        checks = 0

        if signature.get("target") and event_data.get("target") == signature["target"]:
            score += 0.5
            checks += 1

        sig_keywords = set(signature.get("reasoning_keywords", []))
        event_text = " ".join(str(v) for v in event_data.values()).lower()
        if sig_keywords:
            matched = sum(1 for kw in sig_keywords if kw in event_text)
            score += 0.5 * (matched / max(len(sig_keywords), 1))
            checks += 1

        return score / max(checks, 1) if checks > 0 else 0.0

    @staticmethod
    def _extract_keywords(reasoning: list[str]) -> list[str]:
        """Extract key terms from reasoning for pattern matching."""
        keywords = []
        for reason in reasoning:
            words = reason.lower().split()
            keywords.extend(w for w in words if len(w) > 4)
        return list(set(keywords))[:20]

    @staticmethod
    def _running_avg(current: float, new_value: float, count: int) -> float:
        return current + (new_value - current) / count

    async def _on_feedback(self, event: Event) -> None:
        """Process feedback events for learning."""
        data = event.data
        self._human_guidance_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        })

    async def _on_action_approved(self, event: Event) -> None:
        """Track approved actions for learning."""
        pass  # Handled via learn_from_decision
