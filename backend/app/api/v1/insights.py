"""Correlations, security graph, and the project dashboard (all real data)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from sqlalchemy import func, select

from app.api.deps import DbSession, ProjectDep
from app.core import rbac
from app.models.assets import Asset
from app.models.correlation import Correlation
from app.models.detection import Alert
from app.models.enums import (
    AlertStatus,
    AuthorizationStatus,
    FindingStatus,
    Severity,
)
from app.models.scans import Finding, Scan
from app.schemas.misc import (
    CorrelationOut,
    DashboardOut,
    GraphOut,
    SeverityBreakdown,
)
from app.services import correlation_engine
from app.services.graph import build_graph

router = APIRouter(tags=["insights"])


@router.get("/projects/{project_id}/correlations", response_model=list[CorrelationOut])
def list_correlations(project: ProjectDep, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.CORRELATION_READ)
    return db.scalars(select(Correlation).where(Correlation.project_id == obj.id)).all()


@router.post("/projects/{project_id}/correlations/rebuild", response_model=list[CorrelationOut])
def rebuild_correlations(project: ProjectDep, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.CORRELATION_READ)
    return correlation_engine.build_correlations(db, obj.id)


@router.get("/projects/{project_id}/graph", response_model=GraphOut)
def project_graph(project: ProjectDep, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.CORRELATION_READ)
    return build_graph(db, obj.id)


@router.get("/projects/{project_id}/dashboard", response_model=DashboardOut)
def dashboard(project: ProjectDep, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.PROJECT_READ)
    pid = obj.id

    total_assets = db.scalar(select(func.count()).select_from(Asset).where(Asset.project_id == pid)) or 0
    authorized_assets = db.scalar(
        select(func.count()).select_from(Asset).where(
            Asset.project_id == pid,
            Asset.authorization_status == AuthorizationStatus.AUTHORIZED)) or 0

    sev = SeverityBreakdown()
    for s in Severity:
        count = db.scalar(select(func.count()).select_from(Finding).where(
            Finding.project_id == pid, Finding.severity == s)) or 0
        setattr(sev, s.value, count)

    open_findings = db.scalar(select(func.count()).select_from(Finding).where(
        Finding.project_id == pid, Finding.status == FindingStatus.OPEN)) or 0
    active_alerts = db.scalar(select(func.count()).select_from(Alert).where(
        Alert.project_id == pid,
        Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]))) or 0

    week_ago = datetime.now(UTC) - timedelta(days=7)
    recent_scans = db.scalar(select(func.count()).select_from(Scan).where(
        Scan.project_id == pid, Scan.created_at >= week_ago)) or 0

    by_type: dict[str, int] = {}
    for atype, count in db.execute(
        select(Asset.type, func.count()).where(Asset.project_id == pid).group_by(Asset.type)
    ).all():
        by_type[atype.value] = count

    top = db.scalars(select(Finding).where(Finding.project_id == pid)
                     .order_by(Finding.risk_score.desc()).limit(5)).all()
    top_risk = [
        {"id": f.id, "title": f.title, "severity": f.severity.value,
         "risk_score": f.risk_score, "asset_id": f.asset_id, "status": f.status.value}
        for f in top
    ]

    return DashboardOut(
        total_assets=total_assets, authorized_assets=authorized_assets,
        open_findings=open_findings, critical_findings=sev.CRITICAL,
        high_findings=sev.HIGH, active_alerts=active_alerts, recent_scans=recent_scans,
        findings_by_severity=sev, assets_by_type=by_type, top_risk_findings=top_risk,
        generated_at=datetime.now(UTC),
    )
