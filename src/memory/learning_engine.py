"""Self-learning feedback engine for Sentinel-AI.

Tracks analyst verdicts, action outcomes, and false positive rates
to continuously improve agent accuracy.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from src.core.models import Alert, Verdict
from src.memory.vector_store import VectorStore

logger = logging.getLogger(__name__)


class LearningEngine:
    """Self-learning system that improves agent accuracy over time.

    Tracks:
    - Analyst verdicts (true/false positive feedback)
    - Action outcomes (success/failure rates)
    - Environment baselines for anomaly detection
    """

    def __init__(self, vector_store: VectorStore) -> None:
        self._vector_store = vector_store
        self._verdicts: list[dict[str, Any]] = []
        self._action_outcomes: list[dict[str, Any]] = []
        self._baselines: dict[str, dict[str, Any]] = {}

    async def record_verdict(
        self,
        alert_id: str,
        verdict: Verdict,
        analyst_notes: str = "",
        original_verdict: Verdict | None = None,
    ) -> None:
        """Record an analyst verdict for a triaged alert."""
        record = {
            "alert_id": alert_id,
            "verdict": verdict.value,
            "original_verdict": original_verdict.value if original_verdict else None,
            "was_override": original_verdict is not None and original_verdict != verdict,
            "analyst_notes": analyst_notes,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._verdicts.append(record)

        await self._vector_store.store_pattern(
            pattern_id=f"verdict:{alert_id}",
            embedding_text=f"verdict={verdict.value} notes={analyst_notes}",
            metadata=record,
        )

        if record["was_override"]:
            logger.info(
                "Verdict override recorded: alert=%s, original=%s, corrected=%s",
                alert_id,
                original_verdict,
                verdict.value,
            )

    async def record_action_outcome(
        self,
        action_id: str,
        success: bool,
        side_effects: list[str] | None = None,
    ) -> None:
        """Record the outcome of an executed action."""
        record = {
            "action_id": action_id,
            "success": success,
            "side_effects": side_effects or [],
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._action_outcomes.append(record)

    def get_false_positive_rate(self, time_window_days: int = 7) -> float:
        """Calculate false positive rate over a time window."""
        cutoff = datetime.utcnow() - timedelta(days=time_window_days)
        recent = [
            v for v in self._verdicts
            if datetime.fromisoformat(v["timestamp"]) >= cutoff
        ]

        if not recent:
            return 0.0

        false_positives = sum(1 for v in recent if v["verdict"] == Verdict.FALSE_POSITIVE.value)
        return false_positives / len(recent)

    def get_override_rate(self, time_window_days: int = 7) -> float:
        """Calculate how often analysts override agent verdicts."""
        cutoff = datetime.utcnow() - timedelta(days=time_window_days)
        recent = [
            v for v in self._verdicts
            if datetime.fromisoformat(v["timestamp"]) >= cutoff
        ]

        if not recent:
            return 0.0

        overrides = sum(1 for v in recent if v.get("was_override"))
        return overrides / len(recent)

    async def get_similar_past_alerts(self, alert: Alert, n: int = 5) -> list[dict[str, Any]]:
        """Find similar past alerts for context during triage."""
        if not alert.events:
            return []

        query_parts = []
        for event in alert.events[:3]:
            query_parts.append(f"type={event.event_type} severity={event.severity.value}")
            query_parts.extend(f"ioc={ioc.value}" for ioc in event.iocs[:5])

        query = " ".join(query_parts)
        return await self._vector_store.search_similar(query=query, n_results=n)

    async def update_baseline(self, asset_id: str, metrics: dict[str, Any]) -> None:
        """Update the normal behavior baseline for an asset."""
        if asset_id not in self._baselines:
            self._baselines[asset_id] = {
                "metrics_history": [],
                "created_at": datetime.utcnow().isoformat(),
            }

        self._baselines[asset_id]["metrics_history"].append({
            **metrics,
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Keep last 100 data points per asset
        history = self._baselines[asset_id]["metrics_history"]
        if len(history) > 100:
            self._baselines[asset_id]["metrics_history"] = history[-100:]

    def get_baseline(self, asset_id: str) -> dict[str, Any] | None:
        """Get the current baseline for an asset."""
        return self._baselines.get(asset_id)

    def get_action_success_rate(self) -> dict[str, float]:
        """Get success rate grouped by outcome."""
        if not self._action_outcomes:
            return {"total": 0, "success_rate": 0.0}

        successes = sum(1 for o in self._action_outcomes if o["success"])
        return {
            "total": len(self._action_outcomes),
            "success_rate": successes / len(self._action_outcomes),
        }
