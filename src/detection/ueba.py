"""User and Entity Behavior Analytics (UEBA) engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BehaviorBaseline:
    entity_id: str
    entity_type: str  # user, host, service
    metrics: dict[str, dict[str, float]] = field(default_factory=dict)
    # metrics[metric_name] = {mean, std, count, last_updated}
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BehaviorAnomaly:
    entity_id: str
    entity_type: str
    anomaly_type: str
    severity: str
    score: float
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class UEBAEngine:
    """Tracks behavioral baselines per user/host/service and detects deviations."""

    def __init__(self) -> None:
        self._baselines: dict[str, BehaviorBaseline] = {}
        self._anomalies: list[BehaviorAnomaly] = []
        self._alpha = 0.05  # EMA smoothing factor

    def observe(self, entity_id: str, entity_type: str, metrics: dict[str, float]) -> list[BehaviorAnomaly]:
        """Record an observation and detect anomalies against the entity's baseline."""
        key = f"{entity_type}:{entity_id}"
        baseline = self._baselines.get(key)

        if baseline is None:
            # First observation — establish baseline
            baseline = BehaviorBaseline(
                entity_id=entity_id,
                entity_type=entity_type,
            )
            for metric_name, value in metrics.items():
                baseline.metrics[metric_name] = {
                    "mean": value,
                    "std": 0.0,
                    "count": 1,
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                }
            self._baselines[key] = baseline
            return []

        # Compare against baseline and detect anomalies
        anomalies = []
        baseline.last_seen = datetime.now(timezone.utc)

        for metric_name, value in metrics.items():
            if metric_name not in baseline.metrics:
                baseline.metrics[metric_name] = {
                    "mean": value, "std": 0.0, "count": 1,
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                }
                continue

            m = baseline.metrics[metric_name]
            old_mean = m["mean"]
            old_std = m["std"]
            count = m["count"]

            # Z-score anomaly detection
            if old_std > 0 and count >= 10:
                z_score = abs(value - old_mean) / old_std
                if z_score > 3.0:
                    severity = "critical" if z_score > 5.0 else "high" if z_score > 4.0 else "medium"
                    anomaly = BehaviorAnomaly(
                        entity_id=entity_id,
                        entity_type=entity_type,
                        anomaly_type=f"unusual_{metric_name}",
                        severity=severity,
                        score=min(z_score / 5.0, 1.0),
                        details={
                            "metric": metric_name,
                            "observed_value": value,
                            "expected_mean": old_mean,
                            "expected_std": old_std,
                            "z_score": z_score,
                        },
                    )
                    anomalies.append(anomaly)
                    self._anomalies.append(anomaly)

            # Update baseline with EMA
            m["mean"] = (1 - self._alpha) * old_mean + self._alpha * value
            m["std"] = ((1 - self._alpha) * (old_std ** 2 + self._alpha * (value - old_mean) ** 2)) ** 0.5
            m["count"] = count + 1
            m["last_updated"] = datetime.now(timezone.utc).isoformat()

        return anomalies

    def observe_login(self, user_id: str, event: dict[str, Any]) -> list[BehaviorAnomaly]:
        """Specialized observation for login events — detects unusual login patterns."""
        anomalies = []
        key = f"user:{user_id}"
        baseline = self._baselines.get(key)

        # Check for new login location/device
        if baseline:
            known_ips = baseline.metrics.get("_known_ips", {}).get("_values", [])
            login_ip = event.get("source_ip", "")
            if known_ips and login_ip and login_ip not in known_ips:
                anomalies.append(BehaviorAnomaly(
                    entity_id=user_id,
                    entity_type="user",
                    anomaly_type="new_login_location",
                    severity="medium",
                    score=0.6,
                    details={"new_ip": login_ip, "known_ips": known_ips[:10]},
                ))

            # Track the IP
            if "_known_ips" not in baseline.metrics:
                baseline.metrics["_known_ips"] = {"_values": [], "mean": 0, "std": 0, "count": 0, "last_updated": ""}
            ips = baseline.metrics["_known_ips"].get("_values", [])
            if login_ip and login_ip not in ips:
                ips.append(login_ip)
                baseline.metrics["_known_ips"]["_values"] = ips[-50:]  # Keep last 50

        # Standard metric observations
        metrics = {
            "login_hour": float(event.get("hour", datetime.now(timezone.utc).hour)),
            "failed_attempts": float(event.get("failed_attempts", 0)),
        }
        anomalies.extend(self.observe(user_id, "user", metrics))

        return anomalies

    def get_entity_baseline(self, entity_id: str, entity_type: str) -> dict[str, Any] | None:
        key = f"{entity_type}:{entity_id}"
        baseline = self._baselines.get(key)
        if not baseline:
            return None
        return {
            "entity_id": baseline.entity_id,
            "entity_type": baseline.entity_type,
            "first_seen": baseline.first_seen.isoformat(),
            "last_seen": baseline.last_seen.isoformat(),
            "metrics": {k: v for k, v in baseline.metrics.items() if not k.startswith("_")},
        }

    def get_recent_anomalies(self, hours: int = 24) -> list[dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return [
            {
                "entity_id": a.entity_id,
                "entity_type": a.entity_type,
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "score": a.score,
                "details": a.details,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in self._anomalies
            if a.timestamp >= cutoff
        ]

    def get_stats(self) -> dict[str, Any]:
        return {
            "entities_tracked": len(self._baselines),
            "total_anomalies": len(self._anomalies),
            "entity_types": list(set(b.entity_type for b in self._baselines.values())),
        }
