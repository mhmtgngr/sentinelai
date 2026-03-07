"""Executive reporting and KPI endpoints for Sentinel-AI."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request

router = APIRouter()


def _get_brain(request: Request) -> Any:
    return getattr(request.app.state, "brain", None)


@router.get("/executive-summary")
async def executive_summary(request: Request) -> dict[str, Any]:
    """High-level executive summary: open incidents, key metrics, top threats."""
    brain = _get_brain(request)
    if not brain:
        return {"error": "System not initialized"}

    status = brain.get_status()
    decision_stats = status.get("decision_stats", {})
    learning = status.get("learning", {})

    # Incident metrics from responder
    responder = brain._agents.get("incident_responder")
    open_incidents = 0
    recent_incidents: list[dict[str, Any]] = []
    if responder:
        incidents = responder.list_incidents()
        open_incidents = sum(1 for i in incidents if i.get("status") != "closed")
        recent_incidents = incidents[-5:]

    # Compliance from auditor
    auditor = brain._agents.get("compliance_auditor")
    compliance_score = 0.0
    if auditor:
        report = auditor.get_compliance_report()
        compliance_score = report.get("overall_score", 0.0)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system_status": "operational" if status.get("running") else "stopped",
        "mode": status.get("mode", "autonomous"),
        "open_incidents": open_incidents,
        "events_processed": status.get("events_processed", 0),
        "actions_auto_executed": status.get("actions_auto_executed", 0),
        "actions_escalated": status.get("actions_escalated", 0),
        "pending_approvals": status.get("pending_approvals", 0),
        "autonomous_accuracy": decision_stats.get("autonomous_accuracy", 0),
        "compliance_score": compliance_score,
        "recent_incidents": recent_incidents,
        "agents_active": len(status.get("agents", [])),
        "adapters_connected": len(status.get("adapters", [])),
    }


@router.get("/kpis")
async def kpis(request: Request) -> dict[str, Any]:
    """Key Performance Indicators: MTTR, MTTD, detection rate, FP rate."""
    brain = _get_brain(request)
    if not brain:
        return {"error": "System not initialized"}

    status = brain.get_status()
    decision_stats = status.get("decision_stats", {})
    learning = status.get("learning", {})

    # Calculate KPIs
    total_decisions = decision_stats.get("total_decisions", 0)
    auto_approved = decision_stats.get("auto_approved", 0)
    denied = decision_stats.get("denied", 0)

    autonomy_rate = round(auto_approved / max(total_decisions, 1), 3)
    escalation_rate = round(
        decision_stats.get("pending_approval", 0) / max(total_decisions, 1), 3
    )

    # FP rate from learning
    fp_rate = learning.get("false_positive_rate", 0.0)
    autonomous_accuracy = decision_stats.get("autonomous_accuracy", 0.0)

    # MTTR / MTTD estimates from incident responder
    responder = brain._agents.get("incident_responder")
    mttr_minutes = 0.0
    mttd_minutes = 0.0
    if responder:
        incidents = responder.list_incidents()
        closed = [i for i in incidents if i.get("status") == "closed"]
        if closed:
            # Estimate MTTR from incident timeline
            durations = []
            for inc in closed:
                created = inc.get("created_at")
                closed_at = inc.get("closed_at")
                if created and closed_at:
                    try:
                        c = datetime.fromisoformat(str(created))
                        cl = datetime.fromisoformat(str(closed_at))
                        durations.append((cl - c).total_seconds() / 60)
                    except (ValueError, TypeError):
                        pass
            if durations:
                mttr_minutes = round(sum(durations) / len(durations), 1)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mttr_minutes": mttr_minutes,
        "mttd_minutes": mttd_minutes,
        "detection_rate": round(1.0 - fp_rate, 3),
        "false_positive_rate": fp_rate,
        "autonomy_rate": autonomy_rate,
        "escalation_rate": escalation_rate,
        "autonomous_accuracy": autonomous_accuracy,
        "total_decisions": total_decisions,
        "events_processed": status.get("events_processed", 0),
        "cycles": status.get("cycles", 0),
    }


@router.get("/red-team")
async def red_team_report(request: Request) -> dict[str, Any]:
    """Red team campaign results and detection coverage."""
    brain = _get_brain(request)
    if not brain:
        return {"error": "System not initialized"}

    red_team = brain._agents.get("red_team")
    if not red_team:
        return {"error": "Red team agent not registered"}

    campaigns = red_team.list_campaigns()
    templates = red_team.list_campaign_templates()
    history = red_team.get_simulation_history()
    techniques = red_team.list_techniques()

    return {
        "campaigns": campaigns,
        "campaign_templates": templates,
        "simulation_history": history,
        "techniques_available": len(techniques),
        "techniques_by_tactic": _group_by_tactic(techniques),
    }


@router.get("/purple-team")
async def purple_team_report(request: Request) -> dict[str, Any]:
    """ATT&CK coverage matrix, gap analysis, and trends."""
    brain = _get_brain(request)
    if not brain:
        return {"error": "System not initialized"}

    purple_team = brain._agents.get("purple_team")
    if not purple_team:
        return {"error": "Purple team agent not registered"}

    return purple_team.get_coverage_report()


@router.get("/attack-surface")
async def attack_surface_report(request: Request) -> dict[str, Any]:
    """Asset inventory summary and risk distribution."""
    brain = _get_brain(request)
    if not brain:
        return {"error": "System not initialized"}

    asset_inventory = getattr(brain, "asset_inventory", None)
    if not asset_inventory:
        return {"error": "Asset inventory not initialized"}

    surface = asset_inventory.get_attack_surface()
    critical_assets = asset_inventory.get_critical_assets()

    return {
        **surface,
        "critical_assets": [
            {
                "name": a.name,
                "type": a.asset_type.value,
                "risk_score": a.risk_score,
                "vulnerabilities": len(a.vulnerabilities),
                "external_facing": a.external_facing,
            }
            for a in critical_assets
        ],
    }


@router.get("/compliance")
async def compliance_report(request: Request) -> dict[str, Any]:
    """Compliance posture across all frameworks."""
    brain = _get_brain(request)
    if not brain:
        return {"error": "System not initialized"}

    auditor = brain._agents.get("compliance_auditor")
    if not auditor:
        return {"error": "Compliance auditor not registered"}

    return auditor.get_compliance_report()


@router.get("/incidents")
async def incidents_report(request: Request) -> dict[str, Any]:
    """Incident metrics, resolution stats, and cost tracking."""
    brain = _get_brain(request)
    if not brain:
        return {"error": "System not initialized"}

    responder = brain._agents.get("incident_responder")
    if not responder:
        return {"error": "Incident responder not registered"}

    incidents = responder.list_incidents()
    total = len(incidents)
    open_count = sum(1 for i in incidents if i.get("status") != "closed")
    closed_count = total - open_count

    # Severity distribution
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for inc in incidents:
        sev = inc.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        attack = inc.get("attack_type", "unknown")
        by_type[attack] = by_type.get(attack, 0) + 1

    return {
        "total_incidents": total,
        "open": open_count,
        "closed": closed_count,
        "by_severity": by_severity,
        "by_attack_type": by_type,
        "recent": incidents[-10:],
    }


@router.get("/threat-models")
async def threat_models_report(request: Request) -> dict[str, Any]:
    """Threat modeling reports."""
    brain = _get_brain(request)
    if not brain:
        return {"error": "System not initialized"}

    threat_modeler = getattr(brain, "threat_modeler", None)
    if not threat_modeler:
        return {"error": "Threat modeler not initialized"}

    models = threat_modeler.list_models()
    return {"models": models, "count": len(models)}


def _group_by_tactic(techniques: list[dict[str, Any]]) -> dict[str, int]:
    groups: dict[str, int] = {}
    for t in techniques:
        tactic = t.get("tactic", "unknown")
        groups[tactic] = groups.get(tactic, 0) + 1
    return groups
