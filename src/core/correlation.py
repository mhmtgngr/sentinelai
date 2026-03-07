"""Alert correlation engine — links related alerts into incident clusters."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from src.core.models import Alert, AlertCategory, Severity

logger = logging.getLogger(__name__)


class IncidentCluster:
    """A group of correlated alerts forming a potential incident."""

    def __init__(self, cluster_id: str, initial_alert: Alert) -> None:
        self.cluster_id = cluster_id
        self.alerts: list[Alert] = [initial_alert]
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at
        self.categories: set[AlertCategory] = {initial_alert.category}
        self.max_severity = initial_alert.severity
        self.affected_users: set[str] = set()
        self.affected_endpoints: set[str] = set()
        self.affected_ips: set[str] = set()

        if initial_alert.affected_user:
            self.affected_users.add(initial_alert.affected_user)
        if initial_alert.affected_endpoint:
            self.affected_endpoints.add(initial_alert.affected_endpoint)
        if initial_alert.affected_ip:
            self.affected_ips.add(initial_alert.affected_ip)

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        self.updated_at = datetime.now(timezone.utc)
        self.categories.add(alert.category)
        if _severity_rank(alert.severity) > _severity_rank(self.max_severity):
            self.max_severity = alert.severity
        if alert.affected_user:
            self.affected_users.add(alert.affected_user)
        if alert.affected_endpoint:
            self.affected_endpoints.add(alert.affected_endpoint)
        if alert.affected_ip:
            self.affected_ips.add(alert.affected_ip)

    @property
    def is_multi_stage(self) -> bool:
        """True if the cluster spans multiple MITRE tactic stages."""
        return len(self.categories) >= 2

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "alert_count": self.alert_count,
            "categories": [c.value for c in self.categories],
            "max_severity": self.max_severity.value,
            "is_multi_stage": self.is_multi_stage,
            "affected_users": list(self.affected_users),
            "affected_endpoints": list(self.affected_endpoints),
            "affected_ips": list(self.affected_ips),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "alert_ids": [a.id for a in self.alerts],
        }


def _severity_rank(sev: Severity) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}[sev.value]


# Kill-chain progression patterns (adjacent categories that suggest multi-stage attack)
KILL_CHAIN_LINKS: set[tuple[AlertCategory, AlertCategory]] = {
    (AlertCategory.PHISHING, AlertCategory.CREDENTIAL_COMPROMISE),
    (AlertCategory.PHISHING, AlertCategory.MALWARE),
    (AlertCategory.CREDENTIAL_COMPROMISE, AlertCategory.UNAUTHORIZED_ACCESS),
    (AlertCategory.CREDENTIAL_COMPROMISE, AlertCategory.LATERAL_MOVEMENT),
    (AlertCategory.BRUTE_FORCE, AlertCategory.UNAUTHORIZED_ACCESS),
    (AlertCategory.UNAUTHORIZED_ACCESS, AlertCategory.LATERAL_MOVEMENT),
    (AlertCategory.LATERAL_MOVEMENT, AlertCategory.DATA_EXFILTRATION),
    (AlertCategory.MALWARE, AlertCategory.RANSOMWARE),
    (AlertCategory.MALWARE, AlertCategory.LATERAL_MOVEMENT),
    (AlertCategory.UNAUTHORIZED_ACCESS, AlertCategory.DATA_EXFILTRATION),
    (AlertCategory.INSIDER_THREAT, AlertCategory.DATA_EXFILTRATION),
}


class CorrelationEngine:
    """Correlates alerts into incident clusters based on shared attributes and kill-chain patterns."""

    def __init__(self, correlation_window_minutes: int = 60) -> None:
        self._window = timedelta(minutes=correlation_window_minutes)
        self._clusters: dict[str, IncidentCluster] = {}
        # Indexes for fast lookup
        self._user_index: dict[str, list[str]] = defaultdict(list)
        self._endpoint_index: dict[str, list[str]] = defaultdict(list)
        self._ip_index: dict[str, list[str]] = defaultdict(list)
        self._cluster_counter = 0

    def correlate(self, alert: Alert) -> IncidentCluster | None:
        """Try to correlate an alert with an existing cluster, or create a new one.

        Returns the cluster if the alert was correlated to an existing cluster (not a new one).
        """
        candidate_ids: set[str] = set()

        # Find candidate clusters by shared attributes
        if alert.affected_user:
            candidate_ids.update(self._user_index.get(alert.affected_user, []))
        if alert.affected_endpoint:
            candidate_ids.update(self._endpoint_index.get(alert.affected_endpoint, []))
        if alert.affected_ip:
            candidate_ids.update(self._ip_index.get(alert.affected_ip, []))

        now = datetime.now(timezone.utc)
        best_cluster: IncidentCluster | None = None
        best_score = 0.0

        for cid in candidate_ids:
            cluster = self._clusters.get(cid)
            if not cluster:
                continue
            # Check time window
            if now - cluster.updated_at > self._window:
                continue
            score = self._correlation_score(alert, cluster)
            if score > best_score and score >= 0.3:
                best_score = score
                best_cluster = cluster

        if best_cluster:
            best_cluster.add_alert(alert)
            self._index_alert(alert, best_cluster.cluster_id)
            logger.info(
                "Correlated alert %s to cluster %s (score=%.2f, total=%d alerts)",
                alert.id, best_cluster.cluster_id, best_score, best_cluster.alert_count,
            )
            return best_cluster

        # No match — create a new cluster
        self._cluster_counter += 1
        cluster_id = f"INC-{self._cluster_counter:05d}"
        new_cluster = IncidentCluster(cluster_id, alert)
        self._clusters[cluster_id] = new_cluster
        self._index_alert(alert, cluster_id)
        return None

    def _correlation_score(self, alert: Alert, cluster: IncidentCluster) -> float:
        """Score how well an alert fits an existing cluster (0.0 - 1.0)."""
        score = 0.0

        # Shared user
        if alert.affected_user and alert.affected_user in cluster.affected_users:
            score += 0.4

        # Shared endpoint
        if alert.affected_endpoint and alert.affected_endpoint in cluster.affected_endpoints:
            score += 0.3

        # Shared IP
        if alert.affected_ip and alert.affected_ip in cluster.affected_ips:
            score += 0.2

        # Kill-chain progression
        for existing_cat in cluster.categories:
            pair = (existing_cat, alert.category)
            reverse_pair = (alert.category, existing_cat)
            if pair in KILL_CHAIN_LINKS or reverse_pair in KILL_CHAIN_LINKS:
                score += 0.3
                break

        return min(score, 1.0)

    def _index_alert(self, alert: Alert, cluster_id: str) -> None:
        if alert.affected_user:
            if cluster_id not in self._user_index[alert.affected_user]:
                self._user_index[alert.affected_user].append(cluster_id)
        if alert.affected_endpoint:
            if cluster_id not in self._endpoint_index[alert.affected_endpoint]:
                self._endpoint_index[alert.affected_endpoint].append(cluster_id)
        if alert.affected_ip:
            if cluster_id not in self._ip_index[alert.affected_ip]:
                self._ip_index[alert.affected_ip].append(cluster_id)

    def get_cluster(self, cluster_id: str) -> IncidentCluster | None:
        return self._clusters.get(cluster_id)

    def get_active_clusters(self) -> list[IncidentCluster]:
        now = datetime.now(timezone.utc)
        return [
            c for c in self._clusters.values()
            if now - c.updated_at <= self._window
        ]

    def get_multi_stage_clusters(self) -> list[IncidentCluster]:
        return [c for c in self.get_active_clusters() if c.is_multi_stage]

    @property
    def stats(self) -> dict[str, Any]:
        active = self.get_active_clusters()
        return {
            "total_clusters": len(self._clusters),
            "active_clusters": len(active),
            "multi_stage_incidents": len([c for c in active if c.is_multi_stage]),
            "largest_cluster": max((c.alert_count for c in active), default=0),
        }
