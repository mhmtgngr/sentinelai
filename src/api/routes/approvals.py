"""API routes for human-in-the-loop approval workflow."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class ApprovalResponse(BaseModel):
    response: str  # approve, deny, modify
    approved_by: str = "operator"
    notes: str = ""
    new_action: str = ""
    new_target: str = ""


class FeedbackRequest(BaseModel):
    outcome: str  # correct, wrong, false_positive, overreaction, missed_threat
    notes: str = ""


@router.get("/")
async def list_pending_approvals(request: Request) -> list[dict[str, Any]]:
    """Get all decisions waiting for human approval."""
    brain = request.app.state.brain
    pending = brain.decision_engine.get_pending_approvals()
    return [
        {
            "request_id": req.request_id,
            "action": req.decision.action,
            "target": req.decision.target,
            "severity": req.decision.severity,
            "confidence": req.decision.confidence,
            "escalation_reason": req.decision.escalation_reason.value if req.decision.escalation_reason else "",
            "question": req.question,
            "options": req.options,
            "urgency": req.urgency,
            "reasoning": req.decision.reasoning,
            "evidence_count": len(req.decision.evidence),
            "created_at": req.created_at.isoformat(),
        }
        for req in pending
    ]


@router.post("/{decision_id}")
async def respond_to_approval(
    decision_id: str,
    body: ApprovalResponse,
    request: Request,
) -> dict[str, Any]:
    """Approve, deny, or modify a pending decision."""
    brain = request.app.state.brain
    engine = brain.decision_engine

    if body.response == "approve":
        success = engine.approve_decision(decision_id, body.approved_by, body.notes)
    elif body.response == "deny":
        success = engine.deny_decision(decision_id, body.approved_by, body.notes)
    elif body.response == "modify":
        success = engine.modify_and_approve(
            decision_id, body.approved_by, body.new_action, body.new_target, body.notes
        )
    else:
        return {"error": f"Unknown response: {body.response}"}

    if not success:
        return {"error": "Decision not found or already resolved"}

    return {"decision_id": decision_id, "response": body.response, "success": True}


@router.post("/{decision_id}/feedback")
async def submit_feedback(
    decision_id: str,
    body: FeedbackRequest,
    request: Request,
) -> dict[str, Any]:
    """Submit feedback on a past decision (was it correct?).

    This directly feeds into the self-learning system to improve future decisions.
    """
    brain = request.app.state.brain
    result = await brain.record_human_feedback(decision_id, body.outcome, body.notes)
    return result


@router.get("/decisions")
async def list_decisions(
    request: Request,
    limit: int = 50,
    action: str = "",
    status: str = "",
) -> list[dict[str, Any]]:
    """List recent decisions with their outcomes."""
    engine = request.app.state.brain.decision_engine
    decisions = list(engine._decisions.values())

    if action:
        decisions = [d for d in decisions if d.action == action]
    if status == "pending":
        decisions = [d for d in decisions if d.approved is None]
    elif status == "approved":
        decisions = [d for d in decisions if d.approved is True]
    elif status == "denied":
        decisions = [d for d in decisions if d.approved is False]

    decisions = sorted(decisions, key=lambda d: d.created_at, reverse=True)[:limit]

    return [
        {
            "decision_id": d.decision_id,
            "agent": d.agent,
            "action": d.action,
            "target": d.target,
            "severity": d.severity,
            "confidence": d.confidence,
            "requires_approval": d.requires_approval,
            "approved": d.approved,
            "approved_by": d.approved_by,
            "outcome": d.outcome.value,
            "reasoning": d.reasoning,
            "created_at": d.created_at.isoformat(),
        }
        for d in decisions
    ]


@router.get("/learning")
async def get_learning_report(request: Request) -> dict[str, Any]:
    """Get the self-learning system's current report."""
    brain = request.app.state.brain
    return brain.learning.get_learning_report()


@router.get("/stats")
async def get_autonomy_stats(request: Request) -> dict[str, Any]:
    """Get autonomy and decision-making statistics."""
    brain = request.app.state.brain
    return {
        "decision_stats": brain.decision_engine.get_stats(),
        "learning": brain.learning.get_learning_report(),
        "brain": {
            "cycles": brain._cycle_count,
            "events_processed": brain._events_processed,
            "auto_executed": brain._actions_auto_executed,
            "escalated": brain._actions_escalated,
        },
    }
