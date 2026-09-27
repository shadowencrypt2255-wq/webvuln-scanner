"""Findings: list, read, update status/remediation, and technique mapping."""
from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import DbSession, FindingDep, ProjectDep
from app.api.pagination import paginate
from app.core import rbac
from app.models.correlation import FindingTechnique
from app.models.enums import FindingStatus, Severity
from app.models.scans import Finding
from app.schemas.common import Page
from app.schemas.scans import FindingOut, FindingUpdate
from app.services import audit

router = APIRouter(tags=["findings"])


@router.get("/projects/{project_id}/findings", response_model=Page[FindingOut])
def list_findings(project: ProjectDep, db: DbSession,
                  severity: Severity | None = None,
                  status: FindingStatus | None = None,
                  asset_id: int | None = None,
                  cve: str | None = None,
                  page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    obj, ctx = project
    ctx.require(rbac.FINDING_READ)
    stmt = select(Finding).where(Finding.project_id == obj.id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if cve:
        stmt = stmt.where(Finding.cve.ilike(f"%{cve}%"))
    stmt = stmt.order_by(Finding.risk_score.desc())
    return paginate(db, stmt, page, page_size, FindingOut)


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding: FindingDep):
    obj, ctx = finding
    ctx.require(rbac.FINDING_READ)
    return obj


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding: FindingDep, payload: FindingUpdate, db: DbSession):
    obj, ctx = finding
    ctx.require(rbac.FINDING_MANAGE)
    if payload.status is not None:
        obj.status = payload.status
    if payload.remediation is not None:
        obj.remediation = payload.remediation
    db.commit()
    audit.record(db, action="finding.update", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="finding", resource_id=obj.id,
                 meta={"status": obj.status.value})
    return obj


@router.get("/findings/{finding_id}/techniques")
def finding_techniques(finding: FindingDep, db: DbSession):
    obj, ctx = finding
    ctx.require(rbac.FINDING_READ)
    rows = db.scalars(
        select(FindingTechnique).where(FindingTechnique.finding_id == obj.id)
    ).all()
    return [
        {"technique_id": r.technique_id, "relationship_kind": r.relationship_kind,
         "confidence": r.confidence, "evidence": r.evidence}
        for r in rows
    ]
