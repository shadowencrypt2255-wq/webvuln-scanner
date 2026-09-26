"""User, organization, and membership schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import Role


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    full_name: str
    is_active: bool
    is_superuser: bool
    last_login_at: datetime | None = None
    created_at: datetime


class UserWithPermissions(UserOut):
    # Populated per active organization by the /auth/me endpoint.
    organization_id: int | None = None
    role: Role | None = None
    permissions: list[str] = []


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    slug: str
    created_at: datetime


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)


class MembershipOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_id: int
    organization_id: int
    role: Role


class MembershipCreate(BaseModel):
    email: EmailStr
    role: Role = Role.VIEWER


class MembershipUpdate(BaseModel):
    role: Role


class UserAdminCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    full_name: str = ""
    is_superuser: bool = False


class MeOrganization(BaseModel):
    id: int
    name: str
    slug: str
    role: Role
    permissions: list[str]


class MeOut(BaseModel):
    user: UserOut
    organizations: list[MeOrganization]
    is_superuser: bool
