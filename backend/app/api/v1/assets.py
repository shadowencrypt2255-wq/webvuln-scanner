"""Authorized asset inventory and lifecycle."""
from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import AssetDep, DbSession, ProjectDep
from app.api.pagination import paginate
from app.core import rbac
from app.models.assets import Asset
from app.models.base import utcnow
from app.models.enums import (
    AssetLifecycle,
    AssetType,
    AuthorizationStatus,
)
from app.schemas.assets import (
    AssetAuthorize,
    AssetCreate,
    AssetOut,
    AssetUpdate,
)
from app.schemas.common import Message, Page
from app.services import audit

router = APIRouter(tags=["assets"])


@router.get("/projects/{project_id}/assets", response_model=Page[AssetOut])
def list_assets(project: ProjectDep, db: DbSession,
                type: AssetType | None = None,
                authorization_status: AuthorizationStatus | None = None,
                q: str | None = None,
                page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
    obj, ctx = project
    ctx.require(rbac.ASSET_READ)
    stmt = select(Asset).where(Asset.project_id == obj.id)
    if type:
        stmt = stmt.where(Asset.type == type)
    if authorization_status:
        stmt = stmt.where(Asset.authorization_status == authorization_status)
    if q:
        stmt = stmt.where(Asset.value.ilike(f"%{q}%"))
    stmt = stmt.order_by(Asset.created_at.desc())
    return paginate(db, stmt, page, page_size, AssetOut)


@router.post("/projects/{project_id}/assets", response_model=AssetOut, status_code=201)
def create_asset(project: ProjectDep, payload: AssetCreate, db: DbSession):
    obj, ctx = project
    ctx.require(rbac.ASSET_CREATE)
    asset = Asset(
        project_id=obj.id, name=payload.name or payload.value, type=payload.type,
        value=payload.value, criticality=payload.criticality,
        environment=payload.environment, tags=payload.tags,
        discovery_source="manual", lifecycle=AssetLifecycle.DISCOVERED,
    )
    db.add(asset)
    db.commit()
    audit.record(db, action="asset.create", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="asset", resource_id=asset.id,
                 meta={"type": payload.type.value})
    return asset


@router.get("/assets/{asset_id}", response_model=AssetOut)
def get_asset(asset: AssetDep):
    obj, ctx = asset
    ctx.require(rbac.ASSET_READ)
    return obj


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(asset: AssetDep, payload: AssetUpdate, db: DbSession):
    obj, ctx = asset
    ctx.require(rbac.ASSET_UPDATE)
    for field in ("name", "criticality", "environment", "tags", "lifecycle"):
        val = getattr(payload, field)
        if val is not None:
            setattr(obj, field, val)
    db.commit()
    audit.record(db, action="asset.update", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="asset", resource_id=obj.id)
    return obj


@router.post("/assets/{asset_id}/authorize", response_model=AssetOut)
def authorize_asset(asset: AssetDep, payload: AssetAuthorize, db: DbSession):
    obj, ctx = asset
    ctx.require(rbac.ASSET_AUTHORIZE)
    if payload.authorize:
        obj.authorization_status = AuthorizationStatus.AUTHORIZED
        obj.authorization_note = payload.note
        obj.authorized_at = utcnow()
        obj.authorized_by_id = ctx.user.id
        if obj.lifecycle in (AssetLifecycle.DISCOVERED, AssetLifecycle.VERIFIED):
            obj.lifecycle = AssetLifecycle.AUTHORIZED
        action = "asset.authorize"
    else:
        obj.authorization_status = AuthorizationStatus.REVOKED
        obj.authorization_note = payload.note
        action = "asset.revoke_authorization"
    db.commit()
    audit.record(db, action=action, actor_id=ctx.user.id, organization_id=ctx.organization_id,
                 resource_type="asset", resource_id=obj.id, meta={"note": payload.note[:200]})
    return obj


@router.delete("/assets/{asset_id}", response_model=Message)
def delete_asset(asset: AssetDep, db: DbSession):
    obj, ctx = asset
    ctx.require(rbac.ASSET_DELETE)
    db.delete(obj)
    db.commit()
    audit.record(db, action="asset.delete", actor_id=ctx.user.id,
                 organization_id=ctx.organization_id, resource_type="asset", resource_id=obj.id)
    return Message(detail="Asset deleted")
