"""Reports, audit logs, and notifications."""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.api.deps import (
    CurrentUser,
    DbSession,
    OrgContext,
    ProjectDep,
    ReportDep,
)
from app.api.pagination import paginate
from app.core import rbac
from app.models.enums import ReportStatus
from app.models.governance import (
    AuditLog,
    Notification,
    NotificationPreference,
    Report,
)
from app.schemas.common import Message, Page
from app.schemas.misc import (
    AuditLogOut,
    NotificationOut,
    NotificationPrefOut,
    NotificationPrefUpdate,
    ReportCreate,
    ReportOut,
)
from app.services import audit
from app.worker.tasks import enqueue_report

router = APIRouter(tags=["governance"])

_MEDIA = {"PDF": "application/pdf", "CSV": "text/csv", "JSON": "application/json"}


# --- Reports ---
@router.get("/projects/{project_id}/reports", response_model=list[ReportOut])
def list_reports(project: ProjectDep, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.REPORT_READ)
    return db.scalars(select(Report).where(Report.project_id == obj.id)
                      .order_by(Report.created_at.desc())).all()


@router.post("/projects/{project_id}/reports", response_model=ReportOut, status_code=201)
def create_report(project: ProjectDep, payload: ReportCreate, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.REPORT_CREATE)
    report = Report(project_id=obj.id, created_by_id=ctx.user.id,
                    report_type=payload.report_type, fmt=payload.fmt,
                    status=ReportStatus.PENDING)
    db.add(report)
    db.commit()
    audit.record(db, action="report.create", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="report", resource_id=report.id,
                 meta={"type": payload.report_type.value, "format": payload.fmt.value})
    enqueue_report(report.id)
    db.refresh(report)
    return report


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report: ReportDep):
    obj, ctx = report
    ctx.require(rbac.REPORT_READ)
    return obj


@router.get("/reports/{report_id}/download")
def download_report(report: ReportDep):
    obj, ctx = report
    ctx.require(rbac.REPORT_READ)
    if obj.status != ReportStatus.READY or not obj.file_path or not os.path.exists(obj.file_path):
        raise HTTPException(status_code=409, detail="Report is not ready")
    return FileResponse(obj.file_path, media_type=_MEDIA.get(obj.fmt.value, "application/octet-stream"),
                        filename=os.path.basename(obj.file_path))


# --- Audit ---
@router.get("/organizations/{organization_id}/audit", response_model=Page[AuditLogOut])
def list_audit(organization_id: int, ctx: OrgContext, db: DbSession,
               action: str | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    ctx.require(rbac.AUDIT_READ)
    stmt = select(AuditLog).where(AuditLog.organization_id == organization_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    stmt = stmt.order_by(AuditLog.created_at.desc())
    return paginate(db, stmt, page, page_size, AuditLogOut)


# --- Notifications ---
@router.get("/organizations/{organization_id}/notifications", response_model=list[NotificationOut])
def list_notifications(organization_id: int, ctx: OrgContext, db: DbSession,
                       unread_only: bool = False):
    ctx.require(rbac.ORG_READ)
    stmt = select(Notification).where(Notification.organization_id == organization_id)
    if unread_only:
        stmt = stmt.where(Notification.read.is_(False))
    stmt = stmt.order_by(Notification.created_at.desc()).limit(100)
    return db.scalars(stmt).all()


@router.post("/notifications/{notification_id}/read", response_model=Message)
def mark_read(notification_id: int, user: CurrentUser, db: DbSession):
    from app.api.deps import _context_for_org
    n = db.get(Notification, notification_id)
    if n is None:
        raise HTTPException(status_code=404, detail="Not found")
    _context_for_org(db, user, n.organization_id).require(rbac.ORG_READ)
    n.read = True
    db.commit()
    return Message(detail="Marked read")


@router.get("/me/notification-preferences", response_model=NotificationPrefOut)
def get_prefs(user: CurrentUser, db: DbSession):
    pref = db.scalar(select(NotificationPreference).where(NotificationPreference.user_id == user.id))
    if pref is None:
        pref = NotificationPreference(user_id=user.id)
        db.add(pref)
        db.commit()
    return pref


@router.put("/me/notification-preferences", response_model=NotificationPrefOut)
def update_prefs(payload: NotificationPrefUpdate, user: CurrentUser, db: DbSession):
    pref = db.scalar(select(NotificationPreference).where(NotificationPreference.user_id == user.id))
    if pref is None:
        pref = NotificationPreference(user_id=user.id)
        db.add(pref)
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(pref, k, v)
    db.commit()
    return pref
