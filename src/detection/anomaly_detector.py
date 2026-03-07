"""ML-based anomaly detection for network and host events."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    is_anomaly: bool
    anomaly_score: float  # 0.0 = normal, 1.0 = highly anomalous
    feature_contributions: dict[str, float] = field(default_factory=dict)
    method: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AnomalyDetector:
    """Detects anomalies using Isolation Forest and statistical methods.

    Supports both unsupervised anomaly detection (no labels needed) and
    statistical baselines for drift detection.
    """

    def __init__(self, contamination: float = 0.05) -> None:
        self._contamination = contamination
        self._isolation_forest: Any = None
        self._feature_names: list[str] = []
        self._baselines: dict[str, dict[str, float]] = {}  # metric -> {mean, std, min, max}
        self._training_data: list[list[float]] = []
        self._trained = False

    def train(self, feature_matrix: list[list[float]], feature_names: list[str] | None = None) -> None:
        """Train the anomaly detection model on historical data."""
        from sklearn.ensemble import IsolationForest

        self._feature_names = feature_names or [f"f{i}" for i in range(len(feature_matrix[0]))]
        data = np.array(feature_matrix)
        self._training_data = feature_matrix

        self._isolation_forest = IsolationForest(
            contamination=self._contamination,
            n_estimators=200,
            random_state=42,
        )
        self._isolation_forest.fit(data)

        # Compute statistical baselines per feature
        for i, name in enumerate(self._feature_names):
            col = data[:, i]
            self._baselines[name] = {
                "mean": float(np.mean(col)),
                "std": float(np.std(col)),
                "min": float(np.min(col)),
                "max": float(np.max(col)),
                "p95": float(np.percentile(col, 95)),
                "p99": float(np.percentile(col, 99)),
            }

        self._trained = True
        logger.info("AnomalyDetector trained on %d samples with %d features", len(feature_matrix), len(self._feature_names))

    def detect(self, features: list[float]) -> AnomalyResult:
        """Detect if a single sample is anomalous."""
        if not self._trained or self._isolation_forest is None:
            return self._statistical_detect(features)

        sample = np.array([features])
        prediction = self._isolation_forest.predict(sample)[0]
        score = -self._isolation_forest.score_samples(sample)[0]  # Higher = more anomalous
        normalized_score = min(max(score, 0.0), 1.0)

        # Compute per-feature contribution to anomaly
        contributions = {}
        for i, name in enumerate(self._feature_names):
            if name in self._baselines:
                baseline = self._baselines[name]
                std = baseline["std"] if baseline["std"] > 0 else 1.0
                z_score = abs(features[i] - baseline["mean"]) / std
                contributions[name] = min(z_score / 3.0, 1.0)  # Normalize to 0-1

        return AnomalyResult(
            is_anomaly=(prediction == -1),
            anomaly_score=normalized_score,
            feature_contributions=contributions,
            method="isolation_forest",
        )

    def detect_batch(self, feature_matrix: list[list[float]]) -> list[AnomalyResult]:
        """Detect anomalies in a batch of samples."""
        return [self.detect(features) for features in feature_matrix]

    def _statistical_detect(self, features: list[float]) -> AnomalyResult:
        """Fallback statistical anomaly detection when ML model isn't trained."""
        if not self._baselines:
            return AnomalyResult(is_anomaly=False, anomaly_score=0.0, method="no_baseline")

        z_scores = {}
        max_z = 0.0
        for i, name in enumerate(self._feature_names):
            if i < len(features) and name in self._baselines:
                baseline = self._baselines[name]
                std = baseline["std"] if baseline["std"] > 0 else 1.0
                z = abs(features[i] - baseline["mean"]) / std
                z_scores[name] = z
                max_z = max(max_z, z)

        return AnomalyResult(
            is_anomaly=(max_z > 3.0),
            anomaly_score=min(max_z / 5.0, 1.0),
            feature_contributions={k: min(v / 3.0, 1.0) for k, v in z_scores.items()},
            method="statistical",
        )

    def update_baseline(self, metric_name: str, value: float) -> None:
        """Incrementally update a baseline with a new observed value (online learning)."""
        if metric_name not in self._baselines:
            self._baselines[metric_name] = {"mean": value, "std": 0.0, "min": value, "max": value, "p95": value, "p99": value}
            return

        b = self._baselines[metric_name]
        # Exponential moving average
        alpha = 0.01
        old_mean = b["mean"]
        b["mean"] = (1 - alpha) * old_mean + alpha * value
        b["std"] = ((1 - alpha) * (b["std"] ** 2 + alpha * (value - old_mean) ** 2)) ** 0.5
        b["min"] = min(b["min"], value)
        b["max"] = max(b["max"], value)

    def get_baselines(self) -> dict[str, dict[str, float]]:
        return self._baselines.copy()

    @staticmethod
    def extract_network_features(event: dict[str, Any]) -> list[float]:
        """Extract numerical features from a network security event."""
        return [
            float(event.get("bytes_in", 0)),
            float(event.get("bytes_out", 0)),
            float(event.get("packets", 0)),
            float(event.get("duration", 0)),
            float(event.get("port", 0)),
            1.0 if event.get("protocol") == "tcp" else 0.0,
            1.0 if event.get("protocol") == "udp" else 0.0,
            float(event.get("connection_count", 0)),
            float(event.get("failed_attempts", 0)),
            1.0 if event.get("is_encrypted", False) else 0.0,
        ]

    NETWORK_FEATURE_NAMES = [
        "bytes_in", "bytes_out", "packets", "duration", "port",
        "is_tcp", "is_udp", "connection_count", "failed_attempts", "is_encrypted",
    ]
