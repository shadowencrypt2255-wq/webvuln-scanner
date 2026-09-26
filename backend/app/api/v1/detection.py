"""Threat detection API: event ingestion, detection rules, alerts, MITRE."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import or_, select

from app.api.deps import (
    AlertDep,
    CurrentUser,
    DbSession,
    OrgContext,
    ProjectDep,
)
from app.api.pagination import paginate
from app.core import rbac
from app.models.detection import Alert, DetectionRule, MitreTechnique, SecurityEvent
from app.models.enums import AlertStatus
from app.schemas.common import Page
from app.schemas.detection import (
    AlertOut,
    AlertUpdate,
    DetectionRuleCreate,
    DetectionRuleOut,
    DetectionRuleUpdate,
    MitreTechniqueOut,
    SecurityEventBatch,
    SecurityEventOut,
)
from app.services import audit, correlation_engine, detection_engine

router = APIRouter(tags=["detection"])


# --- Events ---
@router.post("/projects/{project_id}/events")
def ingest_events(project: ProjectDep, payload: SecurityEventBatch, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.EVENT_INGEST)
    event_types: set[str] = set()
    for e in payload.events:
        db.add(SecurityEvent(
            project_id=obj.id, event_type=e.event_type, source_ip=e.source_ip,
            username=e.username, path=e.path, user_agent=e.user_agent, outcome=e.outcome,
            occurred_at=e.occurred_at or datetime.now(UTC), raw=e.raw,
        ))
        event_types.add(e.event_type)
    db.commit()

    alerts = detection_engine.run_detection(db, obj.id, ctx.organization_id, event_types)
    if alerts:
        correlation_engine.build_correlations(db, obj.id)
    audit.record(db, action="events.ingest", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="project", resource_id=obj.id,
                 meta={"count": len(payload.events), "alerts_fired": len(alerts)})
    return {"ingested": len(payload.events), "alerts_fired": len(alerts)}


@router.get("/projects/{project_id}/events", response_model=Page[SecurityEventOut])
def list_events(project: ProjectDep, db: DbSession,
                event_type: str | None = None,
                page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    obj, ctx = project
    ctx.require(rbac.EVENT_READ)
    stmt = select(SecurityEvent).where(SecurityEvent.project_id == obj.id)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    stmt = stmt.order_by(SecurityEvent.occurred_at.desc())
    return paginate(db, stmt, page, page_size, SecurityEventOut)


# --- Detection rules ---
@router.get("/organizations/{organization_id}/detection-rules", response_model=list[DetectionRuleOut])
def list_rules(organization_id: int, ctx: OrgContext, db: DbSession):
    ctx.require(rbac.RULE_READ)
    return db.scalars(
        select(DetectionRule).where(
            or_(DetectionRule.organization_id.is_(None),
                DetectionRule.organization_id == organization_id))
        .order_by(DetectionRule.key)
    ).all()


@router.post("/organizations/{organization_id}/detection-rules",
             response_model=DetectionRuleOut, status_code=201)
def create_rule(organization_id: int, payload: DetectionRuleCreate, ctx: OrgContext, db: DbSession):
    ctx.require(rbac.RULE_MANAGE)
    rule = DetectionRule(
        organization_id=organization_id, key=payload.key, name=payload.name,
        description=payload.description, severity=payload.severity, event_type=payload.event_type,
        conditions=payload.conditions, threshold=payload.threshold,
        window_seconds=payload.window_seconds, group_by=payload.group_by,
        mitre_technique_ids=payload.mitre_technique_ids, references=payload.references,
        enabled=payload.enabled,
    )
    db.add(rule)
    db.commit()
    audit.record(db, action="detection_rule.create", actor_id=ctx.user.id,
                 organization_id=organization_id, resource_type="detection_rule", resource_id=rule.id)
    return rule


@router.patch("/detection-rules/{rule_id}", response_model=DetectionRuleOut)
def update_rule(rule_id: int, payload: DetectionRuleUpdate, user: CurrentUser, db: DbSession):
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Not found")
    # Global rules are only editable by platform superusers.
    if rule.organization_id is None:
        if not user.is_superuser:
            raise HTTPException(status_code=403, detail="Global rules require superuser")
    else:
        from app.api.deps import _context_for_org
        ctx = _context_for_org(db, user, rule.organization_id)
        ctx.require(rbac.RULE_MANAGE)
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(rule, k, v)
    rule.version += 1
    db.commit()
    audit.record(db, action="detection_rule.update", actor_id=user.id,
                 organization_id=rule.organization_id, resource_type="detection_rule",
                 resource_id=rule.id)
    return rule


# --- Alerts ---
@router.get("/projects/{project_id}/alerts", response_model=Page[AlertOut])
def list_alerts(project: ProjectDep, db: DbSession,
                status: AlertStatus | None = None,
                page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    obj, ctx = project
    ctx.require(rbac.ALERT_READ)
    stmt = select(Alert).where(Alert.project_id == obj.id)
    if status:
        stmt = stmt.where(Alert.status == status)
    stmt = stmt.order_by(Alert.risk_score.desc(), Alert.last_seen.desc())
    return paginate(db, stmt, page, page_size, AlertOut)


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert: AlertDep):
    obj, ctx = alert
    ctx.require(rbac.ALERT_READ)
    return obj


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert(alert: AlertDep, payload: AlertUpdate, db: DbSession):
    obj, ctx = alert
    ctx.require(rbac.ALERT_MANAGE)
    if payload.status is not None:
        obj.status = payload.status
    if payload.state is not None:
        obj.state = payload.state
    db.commit()
    audit.record(db, action="alert.update", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="alert", resource_id=obj.id,
                 meta={"status": obj.status.value, "state": obj.state.value})
    return obj


# --- MITRE reference ---
@router.get("/mitre/techniques", response_model=list[MitreTechniqueOut])
def list_techniques(user: CurrentUser, db: DbSession, tactic: str | None = None):
    stmt = select(MitreTechnique).order_by(MitreTechnique.technique_id)
    if tactic:
        stmt = stmt.where(MitreTechnique.tactic == tactic)
    return db.scalars(stmt).all()


@router.get("/mitre/techniques/{technique_id}", response_model=MitreTechniqueOut)
def get_technique(technique_id: str, user: CurrentUser, db: DbSession):
    t = db.scalar(select(MitreTechnique).where(MitreTechnique.technique_id == technique_id))
    if t is None:
        raise HTTPException(status_code=404, detail="Technique not found")
    return t
