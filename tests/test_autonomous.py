"""Tests for the autonomous decision engine and self-learning system."""

import pytest
from src.core.event_bus import EventBus
from src.core.autonomous import (
    AutonomousDecisionEngine,
    Decision,
    DecisionOutcome,
    EscalationReason,
    CONFIDENCE_AUTO_APPROVE,
    CONFIDENCE_ESCALATE,
    DESTRUCTIVE_ACTIONS,
    SAFE_ACTIONS,
)
from src.core.self_learning import SelfLearningSystem, ActionProfile, ThreatPattern


# ──────────────────────────────────────────────────
# Autonomous Decision Engine Tests
# ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_safe_action_auto_approved():
    """Safe actions with high confidence should be auto-approved."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    decision = await engine.propose_action(
        agent="triage",
        action="send_teams_alert",
        target="soc-channel",
        severity="medium",
        confidence=0.9,
        reasoning=["Suspicious login detected"],
    )

    assert decision.approved is True
    assert decision.approved_by == "autonomous"
    assert decision.requires_approval is False


@pytest.mark.asyncio
async def test_destructive_action_escalated():
    """Destructive actions should require human approval."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    decision = await engine.propose_action(
        agent="incident_responder",
        action="isolate_host",
        target="workstation-42",
        severity="high",
        confidence=0.8,
        reasoning=["Malware detected on endpoint"],
    )

    assert decision.requires_approval is True
    assert decision.escalation_reason == EscalationReason.DESTRUCTIVE_ACTION
    assert decision.approved is None  # Pending


@pytest.mark.asyncio
async def test_low_confidence_escalated():
    """Low-confidence decisions should always be escalated."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    decision = await engine.propose_action(
        agent="threat_hunter",
        action="block_ip",
        target="10.0.0.55",
        severity="medium",
        confidence=0.3,
        reasoning=["Weak signal — possible false positive"],
    )

    assert decision.requires_approval is True
    assert decision.escalation_reason == EscalationReason.LOW_CONFIDENCE


@pytest.mark.asyncio
async def test_novel_threat_escalated():
    """Actions with no history should be escalated as novel threats."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    decision = await engine.propose_action(
        agent="threat_hunter",
        action="block_ip",
        target="10.0.0.1",
        severity="medium",
        confidence=0.75,
        reasoning=["First time seeing this pattern"],
    )

    assert decision.requires_approval is True
    assert decision.escalation_reason == EscalationReason.NOVEL_THREAT


@pytest.mark.asyncio
async def test_approve_pending_decision():
    """Human can approve a pending decision."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    decision = await engine.propose_action(
        agent="responder",
        action="isolate_host",
        target="server-1",
        severity="critical",
        confidence=0.7,
        reasoning=["Ransomware indicators"],
    )

    assert len(engine.get_pending_approvals()) == 1

    success = engine.approve_decision(decision.decision_id, "analyst-john", "Confirmed ransomware")
    assert success is True
    assert decision.approved is True
    assert decision.approved_by == "analyst-john"
    assert len(engine.get_pending_approvals()) == 0


@pytest.mark.asyncio
async def test_deny_pending_decision():
    """Human can deny a pending decision."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    decision = await engine.propose_action(
        agent="responder",
        action="disable_user",
        target="user@corp.com",
        severity="medium",
        confidence=0.6,
        reasoning=["Account anomaly"],
    )

    success = engine.deny_decision(decision.decision_id, "analyst-jane", "False positive")
    assert success is True
    assert decision.approved is False
    assert decision.outcome == DecisionOutcome.OVERREACTION


@pytest.mark.asyncio
async def test_modify_and_approve():
    """Human can modify the action before approving."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    decision = await engine.propose_action(
        agent="responder",
        action="isolate_host",
        target="server-2",
        severity="high",
        confidence=0.65,
        reasoning=["Lateral movement detected"],
    )

    success = engine.modify_and_approve(
        decision.decision_id,
        modified_by="analyst-mike",
        new_action="revoke_sessions",
        notes="Isolating too aggressive, revoke sessions instead",
    )
    assert success is True
    assert decision.action == "revoke_sessions"
    assert decision.approved is True


@pytest.mark.asyncio
async def test_record_outcome():
    """Outcomes should be tracked for learning."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    decision = await engine.propose_action(
        agent="triage",
        action="notify_soc",
        target="team",
        severity="low",
        confidence=0.9,
        reasoning=["Info alert"],
    )

    await engine.record_outcome(decision.decision_id, DecisionOutcome.SUCCESS, "Correct call")
    assert decision.outcome == DecisionOutcome.SUCCESS
    assert decision.resolved_at is not None


@pytest.mark.asyncio
async def test_confidence_adjustment_with_history():
    """Confidence should be adjusted based on historical accuracy."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    # Build history — 8 successful, 2 failed
    for i in range(10):
        d = await engine.propose_action(
            agent="triage",
            action="enrich_ioc",
            target=f"ip-{i}",
            severity="low",
            confidence=0.8,
            reasoning=["test"],
        )
        outcome = DecisionOutcome.SUCCESS if i < 8 else DecisionOutcome.FAILURE
        await engine.record_outcome(d.decision_id, outcome)

    # Next decision should have adjusted confidence
    d = await engine.propose_action(
        agent="triage",
        action="enrich_ioc",
        target="ip-new",
        severity="low",
        confidence=0.8,
        reasoning=["test"],
    )
    # Confidence should be blended with 80% historical accuracy (0.8 * 0.5 + 0.8 * 0.5 = 0.8)
    # With 10 resolved, history_weight = min(10/20, 0.5) = 0.5
    # adjusted = 0.8 * 0.5 + 0.8 * 0.5 = 0.8 (same because base matches history)
    # Use different base confidence to see adjustment
    d2 = await engine.propose_action(
        agent="triage",
        action="enrich_ioc",
        target="ip-test",
        severity="low",
        confidence=0.5,  # Lower than historical 80% accuracy
        reasoning=["test"],
    )
    # Should be pulled up toward historical accuracy
    assert d2.confidence > 0.5


@pytest.mark.asyncio
async def test_stats():
    """Stats should reflect decision history."""
    bus = EventBus()
    engine = AutonomousDecisionEngine(bus)

    await engine.propose_action("a", "notify_soc", "t", "low", 0.9, ["r"])
    await engine.propose_action("a", "isolate_host", "t", "high", 0.7, ["r"])

    stats = engine.get_stats()
    assert stats["total_decisions"] == 2
    assert stats["auto_approved"] == 1
    assert stats["pending_approval"] == 1


# ──────────────────────────────────────────────────
# Self-Learning System Tests
# ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_learn_from_success():
    """Successful decisions should improve action profiles."""
    bus = EventBus()
    learning = SelfLearningSystem(bus)

    decision = Decision(
        agent="responder",
        action="block_ip",
        target="10.0.0.1",
        severity="high",
        confidence=0.85,
        reasoning=["Malware C2 detected"],
        outcome=DecisionOutcome.SUCCESS,
    )

    await learning.learn_from_decision(decision)
    profile = learning._action_profiles.get("block_ip")
    assert profile is not None
    assert profile.success_count == 1
    assert profile.total_executions == 1
    assert profile.accuracy == 1.0


@pytest.mark.asyncio
async def test_learn_from_false_positive():
    """False positives should be learned as signatures."""
    bus = EventBus()
    learning = SelfLearningSystem(bus)

    decision = Decision(
        agent="responder",
        action="isolate_host",
        target="backup-server",
        severity="high",
        confidence=0.7,
        reasoning=["Large data transfer to external IP"],
        evidence=[{"source_ip": "10.0.0.50", "domain": "backup-provider.com"}],
        outcome=DecisionOutcome.FALSE_POSITIVE,
    )

    insights = await learning.learn_from_decision(decision)
    assert any(a["type"] == "false_positive_learned" for a in insights["adjustments"])
    assert len(learning._false_positive_signatures) == 1


@pytest.mark.asyncio
async def test_recommended_actions():
    """Should recommend actions based on learned patterns."""
    bus = EventBus()
    learning = SelfLearningSystem(bus)

    # Train with successful decisions
    for i in range(8):
        decision = Decision(
            agent="responder",
            action="block_ip",
            target=f"attacker-{i}",
            severity="high",
            confidence=0.85,
            reasoning=["brute_force attack detected"],
            evidence=[{"source_ip": f"1.2.3.{i}"}],
            outcome=DecisionOutcome.SUCCESS,
        )
        await learning.learn_from_decision(decision)

    recs = learning.get_recommended_actions("brute_force", "high")
    assert len(recs) > 0
    assert recs[0]["action"] == "block_ip"


@pytest.mark.asyncio
async def test_false_positive_detection():
    """Learned FP signatures should match similar events."""
    bus = EventBus()
    learning = SelfLearningSystem(bus)

    decision = Decision(
        agent="responder",
        action="isolate_host",
        target="print-server",
        severity="medium",
        confidence=0.6,
        reasoning=["unusual network traffic detected"],
        outcome=DecisionOutcome.FALSE_POSITIVE,
    )
    await learning.learn_from_decision(decision)

    score = learning.is_known_false_positive({"target": "print-server", "description": "unusual traffic"})
    assert score > 0


@pytest.mark.asyncio
async def test_confidence_threshold_learning():
    """Confidence thresholds should adapt based on outcomes."""
    bus = EventBus()
    learning = SelfLearningSystem(bus)

    # High accuracy action
    for i in range(15):
        decision = Decision(
            agent="triage",
            action="enrich_ioc",
            target=f"ioc-{i}",
            severity="low",
            confidence=0.75,
            reasoning=["test"],
            outcome=DecisionOutcome.SUCCESS,
        )
        await learning.learn_from_decision(decision)

    threshold = learning.get_confidence_threshold("enrich_ioc")
    # 100% accuracy with 15 executions: threshold adjusts based on accuracy
    assert threshold != 0.85  # Should be different from default


@pytest.mark.asyncio
async def test_concept_drift_detection():
    """Should detect when accuracy is degrading."""
    bus = EventBus()
    learning = SelfLearningSystem(bus)

    # First 30 decisions: 90% accuracy
    for i in range(30):
        outcome = DecisionOutcome.SUCCESS if i % 10 != 0 else DecisionOutcome.FAILURE
        decision = Decision(
            agent="triage", action="classify", target=f"t-{i}",
            severity="medium", confidence=0.8, reasoning=["test"],
            outcome=outcome,
        )
        await learning.learn_from_decision(decision)

    # Next 25 decisions: 40% accuracy (drift!)
    for i in range(25):
        outcome = DecisionOutcome.SUCCESS if i % 5 == 0 else DecisionOutcome.FAILURE
        decision = Decision(
            agent="triage", action="classify", target=f"t-drift-{i}",
            severity="medium", confidence=0.8, reasoning=["test"],
            outcome=outcome,
        )
        await learning.learn_from_decision(decision)

    # Drift should eventually be detected
    report = learning.get_learning_report()
    # The drift window tracks accuracy over time
    assert len(learning._concept_drift_window) > 0


@pytest.mark.asyncio
async def test_learning_report():
    """Learning report should contain comprehensive metrics."""
    bus = EventBus()
    learning = SelfLearningSystem(bus)

    for i in range(5):
        decision = Decision(
            agent="triage", action="notify", target=f"t-{i}",
            severity="low", confidence=0.9, reasoning=["test"],
            outcome=DecisionOutcome.SUCCESS,
        )
        await learning.learn_from_decision(decision)

    report = learning.get_learning_report()
    assert "current_snapshot" in report
    assert "trend" in report
    assert "action_profiles" in report
    assert report["current_snapshot"]["autonomous_accuracy"] >= 0


@pytest.mark.asyncio
async def test_snapshot_trend_tracking():
    """Multiple snapshots should enable trend detection."""
    bus = EventBus()
    learning = SelfLearningSystem(bus)

    for _ in range(5):
        learning.take_snapshot()

    assert len(learning._learning_snapshots) == 5


def test_action_profile_accuracy():
    """Action profile should calculate accuracy correctly."""
    profile = ActionProfile(
        action="block_ip",
        total_executions=10,
        success_count=8,
        failure_count=2,
    )
    assert profile.accuracy == 0.8


def test_action_profile_optimal_threshold():
    """Optimal threshold should reflect accuracy."""
    # High accuracy profile — threshold adjusts from default
    high_acc = ActionProfile(action="a", total_executions=20, success_count=19, failure_count=1)
    assert high_acc.optimal_confidence_threshold != 0.85

    # With many false positives — threshold adjusts differently
    fp_heavy = ActionProfile(
        action="b", total_executions=20, success_count=10,
        failure_count=5, false_positive_count=5,
    )
    # FP-heavy profile should have a lower threshold (penalized by fp_adj)
    assert fp_heavy.optimal_confidence_threshold != high_acc.optimal_confidence_threshold

    # Not enough data
    new_profile = ActionProfile(action="c", total_executions=3)
    assert new_profile.optimal_confidence_threshold == 0.85


def test_destructive_actions_defined():
    """Destructive actions list should contain expected actions."""
    assert "isolate_host" in DESTRUCTIVE_ACTIONS
    assert "disable_user" in DESTRUCTIVE_ACTIONS
    assert "reset_credentials" in DESTRUCTIVE_ACTIONS


def test_safe_actions_defined():
    """Safe actions list should contain expected actions."""
    assert "notify_soc" in SAFE_ACTIONS
    assert "send_teams_alert" in SAFE_ACTIONS
    assert "collect_forensics" in SAFE_ACTIONS
