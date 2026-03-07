"""Dashboard and metrics endpoints for operational visibility."""

from __future__ import annotations

from fastapi import APIRouter

from src.core.orchestrator import get_orchestrator

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/metrics")
async def get_metrics() -> dict:
    """Get platform-wide operational metrics."""
    orch = get_orchestrator()
    alerts = list(orch.alerts.values())

    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    status_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}

    for alert in alerts:
        severity_counts[alert.severity.value] = (
            severity_counts.get(alert.severity.value, 0) + 1
        )
        status_counts[alert.status.value] = (
            status_counts.get(alert.status.value, 0) + 1
        )
        category_counts[alert.category.value] = (
            category_counts.get(alert.category.value, 0) + 1
        )

    return {
        "total_alerts": len(alerts),
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "category_breakdown": category_counts,
        "dedup_stats": orch.deduplicator.stats,
        "correlation_stats": orch.correlation_engine.stats,
        "threat_intel": {
            "indicators_loaded": orch.threat_intel.indicator_count,
            "enrichments_performed": orch.threat_intel.enrichment_count,
        },
        "audit_entries": orch.audit.total_entries,
    }


@router.get("/incidents")
async def get_incidents(active_only: bool = True) -> list[dict]:
    """List incident clusters from the correlation engine."""
    orch = get_orchestrator()
    if active_only:
        clusters = orch.correlation_engine.get_active_clusters()
    else:
        clusters = list(orch.correlation_engine._clusters.values())
    clusters.sort(key=lambda c: c.updated_at, reverse=True)
    return [c.to_dict() for c in clusters]


@router.get("/incidents/multi-stage")
async def get_multi_stage_incidents() -> list[dict]:
    """List multi-stage attack clusters (kill-chain progressions)."""
    orch = get_orchestrator()
    clusters = orch.correlation_engine.get_multi_stage_clusters()
    clusters.sort(key=lambda c: c.alert_count, reverse=True)
    return [c.to_dict() for c in clusters]


@router.get("/audit")
async def get_audit_log(
    alert_id: str | None = None,
    event_type: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Query the audit trail."""
    orch = get_orchestrator()
    entries = orch.audit.get_entries(
        alert_id=alert_id, event_type=event_type, limit=limit
    )
    return [e.to_dict() for e in entries]


@router.get("/dedup")
async def get_dedup_stats() -> dict:
    """Get alert deduplication statistics."""
    orch = get_orchestrator()
    return orch.deduplicator.stats
