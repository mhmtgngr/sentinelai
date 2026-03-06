"""Detection engine API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from src.detection.anomaly_detector import AnomalyDetector
from src.detection.ueba import UEBAEngine

router = APIRouter()

# Shared instances (in production, these would be managed by the brain)
_anomaly_detector = AnomalyDetector()
_ueba_engine = UEBAEngine()


class AnomalyCheckRequest(BaseModel):
    features: list[float]


class UEBAObservation(BaseModel):
    entity_id: str
    entity_type: str
    metrics: dict[str, float]


@router.post("/anomaly/check")
async def check_anomaly(req: AnomalyCheckRequest) -> dict[str, Any]:
    """Check if a feature vector is anomalous."""
    result = _anomaly_detector.detect(req.features)
    return {
        "is_anomaly": result.is_anomaly,
        "anomaly_score": result.anomaly_score,
        "feature_contributions": result.feature_contributions,
        "method": result.method,
    }


@router.get("/anomaly/baselines")
async def get_baselines() -> dict[str, Any]:
    """Get current anomaly detection baselines."""
    return {"baselines": _anomaly_detector.get_baselines()}


@router.post("/ueba/observe")
async def ueba_observe(obs: UEBAObservation) -> dict[str, Any]:
    """Submit a UEBA observation and get any detected anomalies."""
    anomalies = _ueba_engine.observe(obs.entity_id, obs.entity_type, obs.metrics)
    return {
        "entity_id": obs.entity_id,
        "anomalies_detected": len(anomalies),
        "anomalies": [
            {
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "score": a.score,
                "details": a.details,
            }
            for a in anomalies
        ],
    }


@router.get("/ueba/anomalies")
async def get_recent_anomalies(hours: int = 24) -> dict[str, Any]:
    """Get recent UEBA anomalies."""
    return {"anomalies": _ueba_engine.get_recent_anomalies(hours=hours)}


@router.get("/ueba/stats")
async def ueba_stats() -> dict[str, Any]:
    """Get UEBA engine statistics."""
    return _ueba_engine.get_stats()
