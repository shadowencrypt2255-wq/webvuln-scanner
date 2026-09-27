"""Authentication endpoints: register, login, refresh, me, change-password.

Passwords are hashed with Argon2id. Failed logins are counted and the account
is temporarily locked after a threshold. Login is rate-limited per client IP.
Password reset and email verification are modelled as token-issuing flows; the
delivery channel (email) is pluggable and out of scope for the local build.
"""
from __future__ import annotations

import re
from datetime import UTC

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser
from app.core import rbac
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import SlidingWindowLimiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.models.base import utcnow
from app.models.enums import Role
from app.models.identity import Organization, OrganizationMembership, User
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
)
from app.schemas.common import Message
from app.schemas.identity import MeOrganization, MeOut, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])

_login_limiter = SlidingWindowLimiter(settings.rate_limit_login_per_minute, 60.0)

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str, db: Session) -> str:
    base = _SLUG_RE.sub("-", name.lower()).strip("-") or "org"
    slug, i = base, 1
    while db.scalar(select(Organization).where(Organization.slug == slug)):
        i += 1
        slug = f"{base}-{i}"
    return slug


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.post("/register", response_model=TokenPair, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    existing = db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    db.flush()

    org = Organization(name=payload.organization_name, slug=_slugify(payload.organization_name, db))
    db.add(org)
    db.flush()
    # The registering user becomes ADMIN of their new organization.
    db.add(OrganizationMembership(user_id=user.id, organization_id=org.id, role=Role.ADMIN))
    db.commit()

    audit.record(db, action="user.register", actor_id=user.id, organization_id=org.id,
                 resource_type="user", resource_id=user.id, ip=_client_ip(request))
    return TokenPair(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    ip = _client_ip(request)
    if not _login_limiter.allow(f"{ip}:{payload.email.lower()}"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many login attempts; try again shortly.")

    user = db.scalar(select(User).where(func.lower(User.email) == payload.email.lower()))
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user is None:
        audit.record(db, action="user.login_failed", resource_type="user",
                     result="failure", ip=ip, meta={"email": payload.email.lower()})
        raise invalid

    now = utcnow()
    locked_until = user.locked_until
    if locked_until is not None:
        # SQLite returns naive datetimes; treat stored timestamps as UTC.
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=UTC)
        if locked_until > now:
            raise HTTPException(status_code=status.HTTP_423_LOCKED,
                                detail="Account temporarily locked due to failed logins.")

    if not user.is_active or not verify_password(payload.password, user.hashed_password):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.max_failed_logins:
            from datetime import timedelta
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
        db.commit()
        audit.record(db, action="user.login_failed", actor_id=user.id, resource_type="user",
                     resource_id=user.id, result="failure", ip=ip)
        raise invalid

    # Success — reset counters, opportunistically upgrade the hash.
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(payload.password)
    db.commit()
    _login_limiter.reset(f"{ip}:{payload.email.lower()}")

    audit.record(db, action="user.login", actor_id=user.id, resource_type="user",
                 resource_id=user.id, ip=ip)
    return TokenPair(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenPair:
    try:
        claims = decode_token(payload.refresh_token, expected_type="refresh")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid refresh token") from None
    user = db.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    return TokenPair(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.get("/me", response_model=MeOut)
def me(user: CurrentUser, db: Session = Depends(get_db)) -> MeOut:
    memberships = db.scalars(
        select(OrganizationMembership).where(OrganizationMembership.user_id == user.id)
    ).all()
    orgs = []
    for m in memberships:
        org = db.get(Organization, m.organization_id)
        if org:
            orgs.append(MeOrganization(
                id=org.id, name=org.name, slug=org.slug, role=m.role,
                permissions=sorted(rbac.permissions_for(m.role)),
            ))
    return MeOut(user=UserOut.model_validate(user), organizations=orgs,
                 is_superuser=user.is_superuser)


@router.post("/change-password", response_model=Message)
def change_password(payload: ChangePasswordRequest, request: Request, user: CurrentUser,
                    db: Session = Depends(get_db)) -> Message:
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    audit.record(db, action="user.change_password", actor_id=user.id, resource_type="user",
                 resource_id=user.id, ip=_client_ip(request))
    return Message(detail="Password updated")


@router.post("/logout", response_model=Message)
def logout(request: Request, user: CurrentUser, db: Session = Depends(get_db)) -> Message:
    # Stateless JWT: the client discards its tokens. We record the event.
    audit.record(db, action="user.logout", actor_id=user.id, resource_type="user",
                 resource_id=user.id, ip=_client_ip(request))
    return Message(detail="Logged out")
