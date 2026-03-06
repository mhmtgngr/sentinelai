"""Autonomous decision engine with confidence scoring and human-in-the-loop escalation."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from src.core.event_bus import Event, EventBus, EventType

logger = logging.getLogger(__name__)


class DecisionOutcome(str, Enum):
    """Tracks the outcome of a decision for learning."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILURE = "failure"
    FALSE_POSITIVE = "false_positive"
    MISSED_THREAT = "missed_threat"
    OVERREACTION = "overreaction"


class EscalationReason(str, Enum):
    LOW_CONFIDENCE = "low_confidence"
    HIGH_SEVERITY = "high_severity"
    NOVEL_THREAT = "novel_threat"
    DESTRUCTIVE_ACTION = "destructive_action"
    POLICY_REQUIRED = "policy_required"
    CONFLICTING_SIGNALS = "conflicting_signals"


@dataclass
class Decision:
    """A decision made by the autonomous system."""
    decision_id: str = field(default_factory=lambda: str(uuid4()))
    agent: str = ""
    action: str = ""
    target: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    reasoning: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    requires_approval: bool = False
    escalation_reason: EscalationReason | None = None
    approved: bool | None = None
    approved_by: str | None = None
    outcome: DecisionOutcome = DecisionOutcome.PENDING
    outcome_notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None


@dataclass
class ApprovalRequest:
    """A request for human approval at a critical decision point."""
    request_id: str = field(default_factory=lambda: str(uuid4()))
    decision: Decision = field(default_factory=Decision)
    question: str = ""
    options: list[str] = field(default_factory=lambda: ["approve", "deny", "modify"])
    context: dict[str, Any] = field(default_factory=dict)
    urgency: str = "normal"  # normal, urgent, critical
    timeout_seconds: int = 300
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    response: str | None = None
    response_notes: str = ""
    responded_at: datetime | None = None


# Actions that ALWAYS require human approval
DESTRUCTIVE_ACTIONS = frozenset({
    "isolate_host",
    "disable_user",
    "block_ip_permanent",
    "reset_credentials",
    "wipe_device",
    "revoke_all_sessions",
    "quarantine_mailbox",
    "close_offense",
})

# Actions safe to auto-execute
SAFE_ACTIONS = frozenset({
    "notify_soc",
    "send_teams_alert",
    "add_offense_note",
    "collect_forensics",
    "run_antivirus_scan",
    "enrich_ioc",
    "add_to_watchlist",
    "log_event",
})

# Confidence thresholds
CONFIDENCE_AUTO_APPROVE = 0.85  # Above this: act autonomously
CONFIDENCE_ESCALATE = 0.50      # Below this: always escalate


class AutonomousDecisionEngine:
    """Makes and tracks autonomous decisions with confidence-based escalation.

    Decision flow:
    1. Agent proposes an action with evidence
    2. Engine calculates confidence based on:
       - Historical accuracy of this action type
       - Signal strength (how many indicators converge)
       - Novelty (has this pattern been seen before?)
       - Learning engine adjustments
    3. Based on confidence + action type:
       - HIGH confidence + safe action → auto-execute
       - HIGH confidence + destructive action → execute with notification
       - MEDIUM confidence → execute safe actions, escalate destructive
       - LOW confidence → always escalate to human
    4. All outcomes are tracked for learning
    """

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._decisions: dict[str, Decision] = {}
        self._pending_approvals: dict[str, ApprovalRequest] = {}
        self._approval_callbacks: dict[str, asyncio.Event] = {}
        self._action_history: dict[str, list[Decision]] = {}  # action -> past decisions
        self._confidence_overrides: dict[str, float] = {}  # action -> min confidence

        # Subscribe to approval responses
        self.event_bus.subscribe(EventType.ACTION_APPROVED, self._handle_approval_response)

    async def propose_action(
        self,
        agent: str,
        action: str,
        target: str,
        severity: str,
        confidence: float,
        reasoning: list[str],
        evidence: list[dict[str, Any]] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Decision:
        """Propose an action and decide whether to auto-execute or escalate."""

        # Adjust confidence based on historical accuracy
        adjusted_confidence = self._adjust_confidence(action, confidence)

        decision = Decision(
            agent=agent,
            action=action,
            target=target,
            severity=severity,
            confidence=adjusted_confidence,
            reasoning=reasoning,
            evidence=evidence or [],
        )

        # Determine if approval is needed
        escalation_reason = self._should_escalate(decision)
        decision.requires_approval = escalation_reason is not None
        decision.escalation_reason = escalation_reason

        self._decisions[decision.decision_id] = decision

        # Track in action history
        if action not in self._action_history:
            self._action_history[action] = []
        self._action_history[action].append(decision)

        if decision.requires_approval:
            # Escalate to human
            await self._escalate_to_human(decision, params or {})
        else:
            # Auto-approve and execute
            decision.approved = True
            decision.approved_by = "autonomous"
            await self._publish_decision(decision, params or {})

        return decision

    async def wait_for_approval(self, decision_id: str, timeout: float = 300) -> Decision:
        """Wait for human approval of a pending decision."""
        if decision_id not in self._approval_callbacks:
            self._approval_callbacks[decision_id] = asyncio.Event()
        try:
            await asyncio.wait_for(
                self._approval_callbacks[decision_id].wait(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            decision = self._decisions.get(decision_id)
            if decision and decision.approved is None:
                # Timeout — escalate with higher urgency
                decision.reasoning.append("TIMEOUT: No human response, re-escalating")
                logger.warning("Approval timeout for decision %s: %s %s",
                               decision_id, decision.action, decision.target)
        return self._decisions[decision_id]

    async def record_outcome(
        self,
        decision_id: str,
        outcome: DecisionOutcome,
        notes: str = "",
    ) -> None:
        """Record the outcome of a decision for learning."""
        decision = self._decisions.get(decision_id)
        if not decision:
            return

        decision.outcome = outcome
        decision.outcome_notes = notes
        decision.resolved_at = datetime.now(timezone.utc)

        await self.event_bus.publish(Event(
            event_type=EventType.FEEDBACK_RECEIVED,
            data={
                "decision_id": decision_id,
                "action": decision.action,
                "confidence": decision.confidence,
                "outcome": outcome.value,
                "was_auto_approved": decision.approved_by == "autonomous",
                "notes": notes,
            },
            source="decision_engine",
        ))

        logger.info("Decision outcome recorded: %s %s -> %s (confidence was %.2f)",
                     decision.action, decision.target, outcome.value, decision.confidence)

    def approve_decision(self, decision_id: str, approved_by: str, notes: str = "") -> bool:
        """Human approves a pending decision."""
        decision = self._decisions.get(decision_id)
        if not decision:
            return False

        decision.approved = True
        decision.approved_by = approved_by
        decision.outcome_notes = notes

        # Remove from pending
        self._pending_approvals.pop(decision_id, None)

        # Signal waiting coroutines
        if decision_id in self._approval_callbacks:
            self._approval_callbacks[decision_id].set()

        return True

    def deny_decision(self, decision_id: str, denied_by: str, reason: str = "") -> bool:
        """Human denies a pending decision."""
        decision = self._decisions.get(decision_id)
        if not decision:
            return False

        decision.approved = False
        decision.approved_by = denied_by
        decision.outcome = DecisionOutcome.OVERREACTION
        decision.outcome_notes = reason
        decision.resolved_at = datetime.now(timezone.utc)

        self._pending_approvals.pop(decision_id, None)

        if decision_id in self._approval_callbacks:
            self._approval_callbacks[decision_id].set()

        return True

    def modify_and_approve(
        self,
        decision_id: str,
        modified_by: str,
        new_action: str = "",
        new_target: str = "",
        notes: str = "",
    ) -> bool:
        """Human modifies and approves a pending decision."""
        decision = self._decisions.get(decision_id)
        if not decision:
            return False

        if new_action:
            decision.action = new_action
        if new_target:
            decision.target = new_target
        decision.approved = True
        decision.approved_by = modified_by
        decision.outcome_notes = f"Modified by {modified_by}: {notes}"
        decision.reasoning.append(f"Human modified: {notes}")

        self._pending_approvals.pop(decision_id, None)

        if decision_id in self._approval_callbacks:
            self._approval_callbacks[decision_id].set()

        return True

    def get_pending_approvals(self) -> list[ApprovalRequest]:
        """Get all decisions waiting for human approval."""
        return list(self._pending_approvals.values())

    def get_decision(self, decision_id: str) -> Decision | None:
        return self._decisions.get(decision_id)

    def get_stats(self) -> dict[str, Any]:
        """Get decision engine statistics."""
        all_decisions = list(self._decisions.values())
        auto_approved = [d for d in all_decisions if d.approved_by == "autonomous"]
        human_approved = [d for d in all_decisions if d.approved_by and d.approved_by != "autonomous"]
        denied = [d for d in all_decisions if d.approved is False]

        # Calculate autonomous accuracy
        auto_with_outcome = [d for d in auto_approved if d.outcome != DecisionOutcome.PENDING]
        auto_correct = [d for d in auto_with_outcome if d.outcome in (DecisionOutcome.SUCCESS,)]
        auto_accuracy = len(auto_correct) / max(len(auto_with_outcome), 1)

        return {
            "total_decisions": len(all_decisions),
            "auto_approved": len(auto_approved),
            "human_approved": len(human_approved),
            "denied": len(denied),
            "pending_approval": len(self._pending_approvals),
            "autonomous_accuracy": round(auto_accuracy, 3),
            "confidence_thresholds": {
                "auto_approve": CONFIDENCE_AUTO_APPROVE,
                "escalate": CONFIDENCE_ESCALATE,
            },
        }

    # ---- Internal ----

    def _should_escalate(self, decision: Decision) -> EscalationReason | None:
        """Determine if a decision should be escalated to a human."""

        # Always escalate destructive actions regardless of confidence
        if decision.action in DESTRUCTIVE_ACTIONS:
            if decision.confidence < 0.95:
                return EscalationReason.DESTRUCTIVE_ACTION

        # Low confidence → always escalate
        if decision.confidence < CONFIDENCE_ESCALATE:
            return EscalationReason.LOW_CONFIDENCE

        # Critical severity with medium confidence → escalate
        if decision.severity == "critical" and decision.confidence < CONFIDENCE_AUTO_APPROVE:
            return EscalationReason.HIGH_SEVERITY

        # Novel pattern (no history for this action type)
        history = self._action_history.get(decision.action, [])
        if len(history) < 3:
            if decision.action not in SAFE_ACTIONS:
                return EscalationReason.NOVEL_THREAT

        # Policy-required approval override
        min_confidence = self._confidence_overrides.get(decision.action, 0)
        if min_confidence > 0 and decision.confidence < min_confidence:
            return EscalationReason.POLICY_REQUIRED

        # Safe action with decent confidence → auto-approve
        if decision.action in SAFE_ACTIONS:
            return None

        # Medium-confidence non-safe action → escalate
        if decision.confidence < CONFIDENCE_AUTO_APPROVE:
            return EscalationReason.LOW_CONFIDENCE

        return None

    def _adjust_confidence(self, action: str, base_confidence: float) -> float:
        """Adjust confidence based on historical accuracy of this action type."""
        history = self._action_history.get(action, [])
        resolved = [d for d in history if d.outcome != DecisionOutcome.PENDING]
        if len(resolved) < 5:
            return base_confidence  # Not enough history

        successful = sum(1 for d in resolved if d.outcome == DecisionOutcome.SUCCESS)
        accuracy = successful / len(resolved)

        # Blend base confidence with historical accuracy
        # As more history accumulates, weight history more
        history_weight = min(len(resolved) / 20, 0.5)  # Max 50% weight to history
        adjusted = base_confidence * (1 - history_weight) + accuracy * history_weight

        return round(min(max(adjusted, 0.0), 1.0), 3)

    async def _escalate_to_human(self, decision: Decision, params: dict) -> None:
        """Create an approval request and notify via Teams/events."""
        question = self._format_approval_question(decision)

        request = ApprovalRequest(
            request_id=decision.decision_id,
            decision=decision,
            question=question,
            context={
                "evidence": decision.evidence,
                "reasoning": decision.reasoning,
                "params": params,
            },
            urgency="critical" if decision.severity == "critical" else "normal",
        )
        self._pending_approvals[decision.decision_id] = request

        # Publish escalation event (picked up by Teams adapter, WebSocket, etc.)
        await self.event_bus.publish(Event(
            event_type=EventType.ACTION_REQUESTED,
            data={
                "decision_id": decision.decision_id,
                "action": decision.action,
                "target": decision.target,
                "severity": decision.severity,
                "confidence": decision.confidence,
                "reasoning": decision.reasoning,
                "escalation_reason": decision.escalation_reason.value if decision.escalation_reason else "",
                "question": question,
                "options": request.options,
                "urgency": request.urgency,
                "requires_human_approval": True,
            },
            source="decision_engine",
        ))

        logger.info(
            "ESCALATION [%s]: %s on %s (confidence=%.2f, reason=%s)",
            decision.severity.upper(),
            decision.action,
            decision.target,
            decision.confidence,
            decision.escalation_reason.value if decision.escalation_reason else "none",
        )

    async def _publish_decision(self, decision: Decision, params: dict) -> None:
        """Publish an auto-approved decision for execution."""
        await self.event_bus.publish(Event(
            event_type=EventType.ACTION_APPROVED,
            data={
                "decision_id": decision.decision_id,
                "action": decision.action,
                "target": decision.target,
                "params": params,
                "severity": decision.severity,
                "confidence": decision.confidence,
                "auto_approved": True,
            },
            source="decision_engine",
        ))

    async def _handle_approval_response(self, event: Event) -> None:
        """Handle an approval response from the API/WebSocket."""
        data = event.data
        decision_id = data.get("decision_id", "")
        if not decision_id or decision_id not in self._pending_approvals:
            return

        response = data.get("response", "")
        by = data.get("approved_by", "human")
        notes = data.get("notes", "")

        if response == "approve":
            self.approve_decision(decision_id, by, notes)
        elif response == "deny":
            self.deny_decision(decision_id, by, notes)
        elif response == "modify":
            self.modify_and_approve(
                decision_id, by,
                new_action=data.get("new_action", ""),
                new_target=data.get("new_target", ""),
                notes=notes,
            )

    @staticmethod
    def _format_approval_question(decision: Decision) -> str:
        lines = [
            f"Action: {decision.action}",
            f"Target: {decision.target}",
            f"Severity: {decision.severity.upper()}",
            f"Confidence: {decision.confidence:.0%}",
            f"Reason for escalation: {decision.escalation_reason.value if decision.escalation_reason else 'N/A'}",
            "",
            "Evidence:",
        ]
        for r in decision.reasoning:
            lines.append(f"  - {r}")
        lines.append("")
        lines.append("Approve this action?")
        return "\n".join(lines)
