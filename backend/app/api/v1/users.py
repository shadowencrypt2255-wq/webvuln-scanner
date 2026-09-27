"""Platform administration: user management (superuser only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select

from app.api.deps import DbSession, require_superuser
from app.core.security import hash_password
from app.models.identity import User
from app.schemas.common import Message
from app.schemas.identity import UserAdminCreate, UserOut
from app.services import audit

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_superuser)])


@router.get("/users", response_model=list[UserOut])
def list_users(db: DbSession):
    return db.scalars(select(User).order_by(User.created_at.desc())).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(payload: UserAdminCreate, db: DbSession):
    if db.scalar(select(User).where(func.lower(User.email) == payload.email.lower())):
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(email=payload.email.lower(), hashed_password=hash_password(payload.password),
                full_name=payload.full_name, is_superuser=payload.is_superuser)
    db.add(user)
    db.commit()
    audit.record(db, action="admin.user_create", resource_type="user", resource_id=user.id)
    return user


@router.post("/users/{user_id}/deactivate", response_model=Message)
def deactivate_user(user_id: int, db: DbSession):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Not found")
    user.is_active = False
    db.commit()
    audit.record(db, action="admin.user_deactivate", resource_type="user", resource_id=user.id)
    return Message(detail="User deactivated")


@router.post("/users/{user_id}/activate", response_model=Message)
def activate_user(user_id: int, db: DbSession):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Not found")
    user.is_active = True
    user.failed_login_count = 0
    user.locked_until = None
    db.commit()
    audit.record(db, action="admin.user_activate", resource_type="user", resource_id=user.id)
    return Message(detail="User activated")
