"""Project and asset schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    AssetLifecycle,
    AssetType,
    AuthorizationStatus,
    Criticality,
)


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    organization_id: int
    name: str
    description: str
    created_at: datetime


class AssetCreate(BaseModel):
    name: str = ""
    type: AssetType
    value: str = Field(min_length=1, max_length=1024)
    criticality: Criticality = Criticality.MEDIUM
    environment: str = "production"
    tags: list[str] = []


class AssetUpdate(BaseModel):
    name: str | None = None
    criticality: Criticality | None = None
    environment: str | None = None
    tags: list[str] | None = None
    lifecycle: AssetLifecycle | None = None


class AssetAuthorize(BaseModel):
    authorize: bool = True
    note: str = Field(default="", max_length=2000)


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    name: str
    type: AssetType
    value: str
    authorization_status: AuthorizationStatus
    authorization_note: str
    authorized_at: datetime | None
    lifecycle: AssetLifecycle
    criticality: Criticality
    environment: str
    tags: list
    discovery_source: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


class AssetRelationshipOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source_asset_id: int
    target_asset_id: int
    relation: str
    meta: dict
