"""FastAPI dependencies: authentication, tenant resolution, RBAC enforcement.

Authorization is *always* enforced here on the server. Two independent checks
protect every tenant-scoped resource:

1. **Membership** — the caller must belong to the organization that owns the
   resource; otherwise a 404 is returned (existence is not leaked).
2. **Permission** — the caller's role in that organization must grant the
   required permission; otherwise a 403 is returned.

Platform superusers implicitly hold every permission in every organization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import rbac
from app.core.database import get_db
from app.core.security import decode_token
from app.models.assets import Asset, Project
from app.models.detection import Alert
from app.models.enums import Role
from app.models.governance import Report
from app.models.identity import OrganizationMembership, User
from app.models.scans import Finding, Scan

_bearer = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    request: Request,
    db: DbSession,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(creds.credentials, expected_type="access")
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or unknown user")
    request.state.actor_id = user.id
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_superuser(user: CurrentUser) -> User:
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superuser required")
    return user


@dataclass
class AccessContext:
    user: User
    organization_id: int
    role: Role
    permissions: frozenset[str]

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    def require(self, permission: str) -> None:
        if not self.has(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission}",
            )


def _context_for_org(db: Session, user: User, organization_id: int) -> AccessContext:
    if user.is_superuser:
        return AccessContext(user, organization_id, Role.ADMIN, rbac.ALL_PERMISSIONS)
    membership = db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.organization_id == organization_id,
        )
    )
    if membership is None:
        # Do not reveal that the organization/resource exists.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return AccessContext(user, organization_id, membership.role, rbac.permissions_for(membership.role))


def org_context(organization_id: int, db: DbSession, user: CurrentUser) -> AccessContext:
    return _context_for_org(db, user, organization_id)


OrgContext = Annotated[AccessContext, Depends(org_context)]


# --- Resource loaders: return (object, AccessContext) and enforce tenancy ---

def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


def load_project(project_id: int, db: DbSession, user: CurrentUser) -> tuple[Project, AccessContext]:
    project = db.get(Project, project_id)
    if project is None:
        raise _not_found()
    ctx = _context_for_org(db, user, project.organization_id)
    return project, ctx


ProjectDep = Annotated[tuple[Project, AccessContext], Depends(load_project)]


def load_asset(asset_id: int, db: DbSession, user: CurrentUser) -> tuple[Asset, AccessContext]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise _not_found()
    project = db.get(Project, asset.project_id)
    ctx = _context_for_org(db, user, project.organization_id)
    return asset, ctx


AssetDep = Annotated[tuple[Asset, AccessContext], Depends(load_asset)]


def load_scan(scan_id: int, db: DbSession, user: CurrentUser) -> tuple[Scan, AccessContext]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise _not_found()
    project = db.get(Project, scan.project_id)
    ctx = _context_for_org(db, user, project.organization_id)
    return scan, ctx


ScanDep = Annotated[tuple[Scan, AccessContext], Depends(load_scan)]


def load_finding(finding_id: int, db: DbSession, user: CurrentUser) -> tuple[Finding, AccessContext]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise _not_found()
    project = db.get(Project, finding.project_id)
    ctx = _context_for_org(db, user, project.organization_id)
    return finding, ctx


FindingDep = Annotated[tuple[Finding, AccessContext], Depends(load_finding)]


def load_alert(alert_id: int, db: DbSession, user: CurrentUser) -> tuple[Alert, AccessContext]:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise _not_found()
    project = db.get(Project, alert.project_id)
    ctx = _context_for_org(db, user, project.organization_id)
    return alert, ctx


AlertDep = Annotated[tuple[Alert, AccessContext], Depends(load_alert)]


def load_report(report_id: int, db: DbSession, user: CurrentUser) -> tuple[Report, AccessContext]:
    report = db.get(Report, report_id)
    if report is None:
        raise _not_found()
    project = db.get(Project, report.project_id)
    ctx = _context_for_org(db, user, project.organization_id)
    return report, ctx


ReportDep = Annotated[tuple[Report, AccessContext], Depends(load_report)]
