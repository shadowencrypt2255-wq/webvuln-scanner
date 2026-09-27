"""Transparent, explainable risk scoring.

The score is a weighted sum of five normalized factors, each in [0, 1]. Because
the weights sum to 1.0 and every factor is normalized, the final score is a
bounded 0-100 value whose composition is fully reconstructable — every finding
stores the exact contribution of each factor in ``risk_explanation``.

    risk = 100 * Σ (weight_i · factor_i)
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.models.enums import Confidence, Criticality, Severity

# Factor weights (must sum to 1.0).
WEIGHTS = {
    "severity": 0.45,
    "asset_criticality": 0.20,
    "exposure": 0.15,
    "confidence": 0.10,
    "age": 0.10,
}

_SEVERITY_NORM = {
    Severity.INFO: 0.10,
    Severity.LOW: 0.30,
    Severity.MEDIUM: 0.55,
    Severity.HIGH: 0.80,
    Severity.CRITICAL: 1.00,
}
_CRITICALITY_NORM = {
    Criticality.LOW: 0.30,
    Criticality.MEDIUM: 0.55,
    Criticality.HIGH: 0.80,
    Criticality.CRITICAL: 1.00,
}
_CONFIDENCE_NORM = {
    Confidence.LOW: 0.50,
    Confidence.MEDIUM: 0.80,
    Confidence.HIGH: 1.00,
}
_ENVIRONMENT_EXPOSURE = {
    "production": 1.0,
    "prod": 1.0,
    "staging": 0.7,
    "test": 0.5,
    "development": 0.4,
    "dev": 0.4,
    "internal": 0.4,
}
# Asset types reachable over the network carry more exposure.
_PUBLIC_ASSET_TYPES = {"DOMAIN", "SUBDOMAIN", "IP", "URL", "SERVICE", "API_ENDPOINT", "HOST"}


@dataclass
class RiskInputs:
    severity: Severity
    confidence: Confidence
    asset_criticality: Criticality
    environment: str
    asset_type: str
    first_seen: datetime | None = None


def _age_norm(first_seen: datetime | None) -> float:
    if first_seen is None:
        return 0.2
    now = datetime.now(UTC)
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=UTC)
    days = max(0.0, (now - first_seen).total_seconds() / 86400)
    # Older unresolved findings accrue urgency.
    for limit, val in ((1, 0.2), (7, 0.4), (30, 0.6), (90, 0.8)):
        if days <= limit:
            return val
    return 1.0


def _exposure_norm(environment: str, asset_type: str) -> float:
    base = _ENVIRONMENT_EXPOSURE.get((environment or "").lower(), 0.6)
    if asset_type in _PUBLIC_ASSET_TYPES:
        base = min(1.0, base + 0.1)
    return base


def compute_risk(inputs: RiskInputs) -> tuple[float, dict]:
    factors = {
        "severity": _SEVERITY_NORM.get(inputs.severity, 0.5),
        "asset_criticality": _CRITICALITY_NORM.get(inputs.asset_criticality, 0.55),
        "exposure": _exposure_norm(inputs.environment, inputs.asset_type),
        "confidence": _CONFIDENCE_NORM.get(inputs.confidence, 0.8),
        "age": _age_norm(inputs.first_seen),
    }
    contributions = {k: round(WEIGHTS[k] * v * 100, 2) for k, v in factors.items()}
    score = round(sum(contributions.values()), 1)

    explanation = {
        "score": score,
        "model": "weighted-sum-v1",
        "factors": {
            k: {
                "normalized": round(factors[k], 3),
                "weight": WEIGHTS[k],
                "contribution": contributions[k],
            }
            for k in factors
        },
        "summary": _summarize(score, factors),
    }
    return score, explanation


def _summarize(score: float, factors: dict) -> str:
    band = risk_band(score)
    top = max(factors, key=lambda k: WEIGHTS[k] * factors[k])
    label = top.replace("_", " ")
    return f"{band} risk ({score}/100); the largest driver is {label}."


def risk_band(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Informational"
