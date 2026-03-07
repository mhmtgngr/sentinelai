"""ML-based threat classification for known attack types."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

ATTACK_LABELS = [
    "normal",
    "brute_force",
    "sql_injection",
    "xss",
    "port_scan",
    "dos",
    "malware_c2",
    "data_exfiltration",
    "lateral_movement",
    "privilege_escalation",
]


@dataclass
class ClassificationResult:
    predicted_class: str
    confidence: float
    class_probabilities: dict[str, float] = field(default_factory=dict)
    method: str = ""


class ThreatClassifier:
    """Supervised classifier for categorizing security events into known attack types.

    Uses Random Forest with an ensemble approach for robust multi-class classification.
    """

    def __init__(self) -> None:
        self._model: Any = None
        self._scaler: Any = None
        self._feature_names: list[str] = []
        self._labels = ATTACK_LABELS
        self._trained = False

    def train(self, feature_matrix: list[list[float]], labels: list[str], feature_names: list[str] | None = None) -> dict[str, Any]:
        """Train the classifier on labeled security event data."""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        from sklearn.model_selection import cross_val_score

        self._feature_names = feature_names or [f"f{i}" for i in range(len(feature_matrix[0]))]

        X = np.array(feature_matrix)
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        le = LabelEncoder()
        y = le.fit_transform(labels)
        self._labels = list(le.classes_)

        self._model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled, y)

        # Cross-validation score
        cv_scores = cross_val_score(self._model, X_scaled, y, cv=min(5, len(set(labels))), scoring="f1_weighted")

        self._trained = True
        logger.info("ThreatClassifier trained. CV F1: %.3f (+/- %.3f)", cv_scores.mean(), cv_scores.std())

        return {
            "cv_f1_mean": float(cv_scores.mean()),
            "cv_f1_std": float(cv_scores.std()),
            "classes": self._labels,
            "n_samples": len(labels),
            "feature_importances": dict(zip(self._feature_names, map(float, self._model.feature_importances_))),
        }

    def classify(self, features: list[float]) -> ClassificationResult:
        """Classify a single event."""
        if not self._trained or self._model is None:
            return ClassificationResult(predicted_class="unknown", confidence=0.0, method="untrained")

        X = np.array([features])
        X_scaled = self._scaler.transform(X)

        prediction = self._model.predict(X_scaled)[0]
        probabilities = self._model.predict_proba(X_scaled)[0]

        predicted_class = self._labels[prediction]
        class_probs = {label: float(prob) for label, prob in zip(self._labels, probabilities)}

        return ClassificationResult(
            predicted_class=predicted_class,
            confidence=float(max(probabilities)),
            class_probabilities=class_probs,
            method="random_forest",
        )

    def classify_batch(self, feature_matrix: list[list[float]]) -> list[ClassificationResult]:
        """Classify a batch of events."""
        if not self._trained or self._model is None:
            return [ClassificationResult(predicted_class="unknown", confidence=0.0, method="untrained")
                    for _ in feature_matrix]

        X = np.array(feature_matrix)
        X_scaled = self._scaler.transform(X)
        predictions = self._model.predict(X_scaled)
        probabilities = self._model.predict_proba(X_scaled)

        results = []
        for pred, probs in zip(predictions, probabilities):
            class_probs = {label: float(prob) for label, prob in zip(self._labels, probs)}
            results.append(ClassificationResult(
                predicted_class=self._labels[pred],
                confidence=float(max(probs)),
                class_probabilities=class_probs,
                method="random_forest",
            ))
        return results

    def get_feature_importance(self) -> dict[str, float]:
        """Return feature importance scores from the trained model."""
        if not self._trained or self._model is None:
            return {}
        return dict(zip(self._feature_names, map(float, self._model.feature_importances_)))
