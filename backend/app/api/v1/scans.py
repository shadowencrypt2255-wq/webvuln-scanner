"""Scan lifecycle: create (authorization-gated), list, read, cancel."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.api.deps import DbSession, ProjectDep, ScanDep
from app.api.pagination import paginate
from app.core import rbac
from app.models.assets import Asset
from app.models.enums import AuthorizationStatus, ScanStatus
from app.models.scans import Finding, Scan
from app.schemas.common import Page
from app.schemas.scans import FindingOut, ScanCreate, ScanOut
from app.services import audit
from app.worker.tasks import enqueue_scan

router = APIRouter(tags=["scans"])


@router.get("/projects/{project_id}/scans", response_model=Page[ScanOut])
def list_scans(project: ProjectDep, db: DbSession,
               status: ScanStatus | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    obj, ctx = project
    ctx.require(rbac.SCAN_READ)
    stmt = select(Scan).where(Scan.project_id == obj.id)
    if status:
        stmt = stmt.where(Scan.status == status)
    stmt = stmt.order_by(Scan.created_at.desc())
    return paginate(db, stmt, page, page_size, ScanOut)


@router.post("/projects/{project_id}/scans", response_model=ScanOut, status_code=201)
def create_scan(project: ProjectDep, payload: ScanCreate, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.SCAN_CREATE)

    asset = db.get(Asset, payload.asset_id)
    if asset is None or asset.project_id != obj.id:
        raise HTTPException(status_code=404, detail="Asset not found in this project")
    if asset.authorization_status != AuthorizationStatus.AUTHORIZED:
        raise HTTPException(status_code=403,
                            detail="Asset must be AUTHORIZED before it can be scanned")

    config = {"skip_auth_bruteforce": payload.skip_auth_bruteforce}
    if payload.max_pages:
        config["max_pages"] = payload.max_pages

    scan = Scan(
        project_id=obj.id, asset_id=asset.id, created_by_id=ctx.user.id,
        scan_type=payload.scan_type, status=ScanStatus.QUEUED,
        config=config, target=asset.value,
    )
    db.add(scan)
    db.commit()
    audit.record(db, action="scan.create", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="scan", resource_id=scan.id,
                 meta={"asset_id": asset.id, "scan_type": payload.scan_type.value})

    # Eager (dev/test) → runs inline; broker configured (prod) → dispatched.
    enqueue_scan(scan.id)
    db.refresh(scan)
    return scan


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan: ScanDep):
    obj, ctx = scan
    ctx.require(rbac.SCAN_READ)
    return obj


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan: ScanDep, db: DbSession):
    obj, ctx = scan
    ctx.require(rbac.SCAN_CANCEL)
    if obj.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        obj.cancel_requested = True
        if obj.status == ScanStatus.QUEUED:
            obj.status = ScanStatus.CANCELLED
        db.commit()
        audit.record(db, action="scan.cancel", actor_id=ctx.user.id,
                     organization_id=ctx.organization_id, resource_type="scan", resource_id=obj.id)
    return obj


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def scan_findings(scan: ScanDep, db: DbSession):
    obj, ctx = scan
    ctx.require(rbac.FINDING_READ)
    return db.scalars(select(Finding).where(Finding.scan_id == obj.id)
                      .order_by(Finding.risk_score.desc())).all()
