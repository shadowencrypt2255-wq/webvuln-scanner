from datetime import UTC, datetime, timedelta

from app.models.enums import Confidence, Criticality, Severity
from app.services.risk_engine import RiskInputs, compute_risk, risk_band


def test_risk_is_bounded_and_explained():
    score, explanation = compute_risk(RiskInputs(
        severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        asset_criticality=Criticality.CRITICAL, environment="production",
        asset_type="URL", first_seen=datetime.now(UTC) - timedelta(days=120),
    ))
    assert 0.0 <= score <= 100.0
    assert score > 80  # critical/critical/prod/high-confidence/old = very high
    assert set(explanation["factors"]) == {
        "severity", "asset_criticality", "exposure", "confidence", "age"}
    # Contributions must sum to the score (transparency guarantee).
    total = sum(f["contribution"] for f in explanation["factors"].values())
    assert abs(total - score) < 0.5


def test_higher_severity_scores_higher():
    common = dict(confidence=Confidence.HIGH, asset_criticality=Criticality.MEDIUM,
                  environment="production", asset_type="URL",
                  first_seen=datetime.now(UTC))
    low, _ = compute_risk(RiskInputs(severity=Severity.LOW, **common))
    high, _ = compute_risk(RiskInputs(severity=Severity.HIGH, **common))
    assert high > low


def test_lower_criticality_reduces_score():
    common = dict(severity=Severity.HIGH, confidence=Confidence.HIGH,
                  environment="production", asset_type="URL",
                  first_seen=datetime.now(UTC))
    crit, _ = compute_risk(RiskInputs(asset_criticality=Criticality.CRITICAL, **common))
    low, _ = compute_risk(RiskInputs(asset_criticality=Criticality.LOW, **common))
    assert crit > low


def test_risk_band_thresholds():
    assert risk_band(85) == "Critical"
    assert risk_band(65) == "High"
    assert risk_band(40) == "Medium"
    assert risk_band(20) == "Low"
    assert risk_band(5) == "Informational"
