"""Correlation engine: builds *explained* relationships between entities.

Correlations are never arbitrary — each edge stores a ``reason``. The engine
recomputes the auto-generated edges for a project (edges tagged
``meta.auto == True``) and leaves any manually-created edges intact.

Two concrete correlations are produced:

1. **alert-entity -> asset** — an alert's entity (e.g. a source IP) matches an
   authorized asset's value, tying observed activity to a known asset.
2. **finding <-> alert (shared technique)** — a finding carries a POTENTIAL
   MITRE technique that an alert reports as observed; the vulnerability may have
   enabled the detected activity. Such alerts are elevated to CORRELATED.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.assets import Asset
from app.models.correlation import Correlation, FindingTechnique
from app.models.detection import Alert
from app.models.enums import AlertState, AlertStatus
from app.models.scans import Finding


def _clear_auto(db: Session, project_id: int) -> None:
    for c in db.scalars(select(Correlation).where(Correlation.project_id == project_id)).all():
        if (c.meta or {}).get("auto"):
            db.delete(c)


def build_correlations(db: Session, project_id: int) -> list[Correlation]:
    _clear_auto(db, project_id)
    created: list[Correlation] = []

    alerts = db.scalars(
        select(Alert).where(
            Alert.project_id == project_id,
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
        )
    ).all()
    assets = db.scalars(select(Asset).where(Asset.project_id == project_id)).all()
    asset_by_value = {a.value: a for a in assets}

    # 1. alert entity -> asset
    for alert in alerts:
        if alert.entity and alert.entity in asset_by_value:
            asset = asset_by_value[alert.entity]
            created.append(_add(db, project_id, "alert", alert.id, "asset", asset.id,
                                "targets",
                                f"Alert entity {alert.entity!r} matches authorized asset "
                                f"{asset.value!r}.", weight=1.0))

    # 2. finding <-> alert on shared MITRE technique
    finding_techs = db.scalars(
        select(FindingTechnique).join(Finding, Finding.id == FindingTechnique.finding_id)
        .where(Finding.project_id == project_id)
    ).all()
    techs_by_finding: dict[int, set[str]] = {}
    for ft in finding_techs:
        techs_by_finding.setdefault(ft.finding_id, set()).add(ft.technique_id)

    for alert in alerts:
        alert_techs = set(alert.mitre_technique_ids or [])
        if not alert_techs:
            continue
        for finding_id, ftechs in techs_by_finding.items():
            shared = alert_techs & ftechs
            if not shared:
                continue
            techs = ", ".join(sorted(shared))
            created.append(_add(
                db, project_id, "finding", finding_id, "alert", alert.id, "enables",
                f"Finding's potential technique(s) {techs} match the alert's observed "
                f"technique(s); the vulnerability may have enabled this activity.",
                weight=2.0, extra={"shared_techniques": sorted(shared)},
            ))
            if alert.state in (AlertState.OBSERVED, AlertState.SUSPICIOUS):
                alert.state = AlertState.CORRELATED
                alert.risk_score = min(100.0, alert.risk_score + 10.0)

    db.commit()
    return created


def _add(db: Session, project_id: int, s_type: str, s_id: int, t_type: str, t_id: int,
         relation: str, reason: str, weight: float = 1.0, extra: dict | None = None) -> Correlation:
    meta = {"auto": True}
    if extra:
        meta.update(extra)
    c = Correlation(
        project_id=project_id, source_type=s_type, source_id=s_id,
        target_type=t_type, target_id=t_id, relation=relation,
        reason=reason, weight=weight, meta=meta,
    )
    db.add(c)
    db.flush()
    return c
