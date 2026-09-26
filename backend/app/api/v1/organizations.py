"""Organization and membership (team/RBAC) management."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select

from app.api.deps import CurrentUser, DbSession, OrgContext
from app.core import rbac
from app.models.enums import Role
from app.models.identity import Organization, OrganizationMembership, User
from app.schemas.common import Message
from app.schemas.identity import (
    MembershipCreate,
    MembershipOut,
    MembershipUpdate,
    OrganizationCreate,
    OrganizationOut,
)
from app.services import audit

router = APIRouter(tags=["organizations"])
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str, db) -> str:
    base = _SLUG_RE.sub("-", name.lower()).strip("-") or "org"
    slug, i = base, 1
    while db.scalar(select(Organization).where(Organization.slug == slug)):
        i += 1
        slug = f"{base}-{i}"
    return slug


@router.get("/organizations", response_model=list[OrganizationOut])
def list_organizations(user: CurrentUser, db: DbSession):
    if user.is_superuser:
        return db.scalars(select(Organization)).all()
    org_ids = db.scalars(
        select(OrganizationMembership.organization_id).where(
            OrganizationMembership.user_id == user.id)
    ).all()
    if not org_ids:
        return []
    return db.scalars(select(Organization).where(Organization.id.in_(org_ids))).all()


@router.post("/organizations", response_model=OrganizationOut, status_code=201)
def create_organization(payload: OrganizationCreate, user: CurrentUser, db: DbSession):
    org = Organization(name=payload.name, slug=_slugify(payload.name, db))
    db.add(org)
    db.flush()
    db.add(OrganizationMembership(user_id=user.id, organization_id=org.id, role=Role.ADMIN))
    db.commit()
    audit.record(db, action="organization.create", actor_id=user.id, organization_id=org.id,
                 resource_type="organization", resource_id=org.id)
    return org


@router.get("/organizations/{organization_id}", response_model=OrganizationOut)
def get_organization(organization_id: int, ctx: OrgContext, db: DbSession):
    ctx.require(rbac.ORG_READ)
    return db.get(Organization, organization_id)


@router.get("/organizations/{organization_id}/members", response_model=list[MembershipOut])
def list_members(organization_id: int, ctx: OrgContext, db: DbSession):
    ctx.require(rbac.ORG_READ)
    return db.scalars(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id)
    ).all()


@router.post("/organizations/{organization_id}/members", response_model=MembershipOut, status_code=201)
def add_member(organization_id: int, payload: MembershipCreate, ctx: OrgContext,
               request: Request, db: DbSession):
    ctx.require(rbac.USER_MANAGE)
    target = db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))
    if target is None:
        raise HTTPException(status_code=404, detail="No user with that email")
    existing = db.scalar(select(OrganizationMembership).where(
        OrganizationMembership.organization_id == organization_id,
        OrganizationMembership.user_id == target.id))
    if existing:
        raise HTTPException(status_code=409, detail="User is already a member")
    m = OrganizationMembership(user_id=target.id, organization_id=organization_id, role=payload.role)
    db.add(m)
    db.commit()
    audit.record(db, action="member.add", actor_id=ctx.user.id, organization_id=organization_id,
                 resource_type="membership", resource_id=m.id,
                 meta={"target_user": target.id, "role": payload.role.value})
    return m


@router.patch("/organizations/{organization_id}/members/{membership_id}", response_model=MembershipOut)
def update_member(organization_id: int, membership_id: int, payload: MembershipUpdate,
                  ctx: OrgContext, db: DbSession):
    ctx.require(rbac.USER_MANAGE)
    m = db.get(OrganizationMembership, membership_id)
    if m is None or m.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Not found")
    # Guard against removing the last admin.
    if m.role == Role.ADMIN and payload.role != Role.ADMIN:
        admins = db.scalar(select(func.count()).select_from(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.role == Role.ADMIN))
        if admins <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote the last admin")
    m.role = payload.role
    db.commit()
    audit.record(db, action="member.update_role", actor_id=ctx.user.id,
                 organization_id=organization_id, resource_type="membership", resource_id=m.id,
                 meta={"role": payload.role.value})
    return m


@router.delete("/organizations/{organization_id}/members/{membership_id}", response_model=Message)
def remove_member(organization_id: int, membership_id: int, ctx: OrgContext, db: DbSession):
    ctx.require(rbac.USER_MANAGE)
    m = db.get(OrganizationMembership, membership_id)
    if m is None or m.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Not found")
    if m.role == Role.ADMIN:
        admins = db.scalar(select(func.count()).select_from(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.role == Role.ADMIN))
        if admins <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the last admin")
    db.delete(m)
    db.commit()
    audit.record(db, action="member.remove", actor_id=ctx.user.id, organization_id=organization_id,
                 resource_type="membership", resource_id=membership_id)
    return Message(detail="Member removed")
