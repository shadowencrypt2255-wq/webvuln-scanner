"""Detection engine: evaluates declarative detection rules against security
events and raises/updates alerts.

A rule matches events of ``event_type`` within a sliding ``window_seconds``,
optionally filtered by ``conditions.match`` and grouped by ``group_by`` fields.
When a group's event count reaches ``threshold`` an alert is created or updated
(de-duplicated by rule + group), moving to the SUSPICIOUS state.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.detection import Alert, DetectionRule, SecurityEvent
from app.models.enums import AlertState, AlertStatus, Severity

_SEVERITY_BASE = {
    Severity.INFO: 10.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 45.0,
    Severity.HIGH: 70.0,
    Severity.CRITICAL: 90.0,
}

_EVENT_FIELDS = {"source_ip", "username", "path", "user_agent", "outcome", "event_type"}


def _alert_risk(severity: Severity, event_count: int) -> float:
    base = _SEVERITY_BASE.get(severity, 40.0)
    # Volume nudges risk upward but is capped so it never dominates severity.
    bump = min(15.0, (event_count - 1) * 1.5)
    return round(min(100.0, base + bump), 1)


def _matches_conditions(event: SecurityEvent, conditions: dict) -> bool:
    match = (conditions or {}).get("match", {})
    for field, expected in match.items():
        if field not in _EVENT_FIELDS:
            continue
        if getattr(event, field, None) != expected:
            return False
    return True


def _group_value(event: SecurityEvent, group_by: list[str]) -> str:
    if not group_by:
        return "*"
    return "|".join(f"{k}={getattr(event, k, '')}" for k in group_by if k in _EVENT_FIELDS)


def evaluate_rule(db: Session, project_id: int, rule: DetectionRule,
                  now: datetime | None = None) -> list[Alert]:
    if not rule.enabled:
        return []
    now = now or datetime.now(UTC)
    window_start = now - timedelta(seconds=rule.window_seconds)

    stmt = select(SecurityEvent).where(
        SecurityEvent.project_id == project_id,
        SecurityEvent.occurred_at >= window_start,
        SecurityEvent.occurred_at <= now,
    )
    if rule.event_type:
        stmt = stmt.where(SecurityEvent.event_type == rule.event_type)

    events = [e for e in db.scalars(stmt).all() if _matches_conditions(e, rule.conditions)]

    groups: dict[str, list[SecurityEvent]] = {}
    for e in events:
        groups.setdefault(_group_value(e, rule.group_by), []).append(e)

    fired: list[Alert] = []
    for group_value, group_events in groups.items():
        if len(group_events) < rule.threshold:
            continue
        fired.append(_upsert_alert(db, project_id, rule, group_value, group_events, now))
    if fired:
        db.commit()
    return fired


def _upsert_alert(db: Session, project_id: int, rule: DetectionRule,
                  group_value: str, group_events: list[SecurityEvent],
                  now: datetime) -> Alert:
    dedup_key = f"{rule.key}|{group_value}"
    entity = ""
    if rule.group_by:
        first = group_events[0]
        entity = getattr(first, rule.group_by[0], "") or ""

    alert = db.scalar(
        select(Alert).where(
            Alert.project_id == project_id,
            Alert.dedup_key == dedup_key,
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
        )
    )
    count = len(group_events)
    sample = [
        {"event_type": e.event_type, "source_ip": e.source_ip,
         "username": e.username, "path": e.path, "outcome": e.outcome,
         "occurred_at": e.occurred_at.isoformat()}
        for e in sorted(group_events, key=lambda e: e.occurred_at)[-5:]
    ]
    evidence = {
        "rule": rule.key,
        "group": group_value,
        "window_seconds": rule.window_seconds,
        "threshold": rule.threshold,
        "match_count": count,
        "sample_events": sample,
    }

    if alert:
        alert.event_count = count
        alert.last_seen = now
        alert.evidence = evidence
        alert.risk_score = _alert_risk(rule.severity, count)
        if alert.state == AlertState.OBSERVED:
            alert.state = AlertState.SUSPICIOUS
        return alert

    alert = Alert(
        project_id=project_id,
        rule_id=rule.id,
        title=f"{rule.name} ({entity})" if entity else rule.name,
        severity=rule.severity,
        state=AlertState.SUSPICIOUS,
        status=AlertStatus.OPEN,
        dedup_key=dedup_key,
        entity=entity,
        event_count=count,
        evidence=evidence,
        mitre_technique_ids=list(rule.mitre_technique_ids or []),
        risk_score=_alert_risk(rule.severity, count),
        first_seen=now,
        last_seen=now,
    )
    db.add(alert)
    db.flush()
    return alert


def run_detection(db: Session, project_id: int, organization_id: int,
                  event_types: set[str] | None = None) -> list[Alert]:
    """Run all enabled rules (global + org-scoped) for a project."""
    stmt = select(DetectionRule).where(
        DetectionRule.enabled.is_(True),
        (DetectionRule.organization_id.is_(None))
        | (DetectionRule.organization_id == organization_id),
    )
    rules = db.scalars(stmt).all()
    fired: list[Alert] = []
    for rule in rules:
        if event_types and rule.event_type and rule.event_type not in event_types:
            continue
        fired.extend(evaluate_rule(db, project_id, rule))
    return fired
