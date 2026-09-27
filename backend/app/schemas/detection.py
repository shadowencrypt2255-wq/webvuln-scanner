"""Security event, detection rule, alert, and MITRE schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import AlertState, AlertStatus, Severity


class SecurityEventIn(BaseModel):
    event_type: str = Field(min_length=1, max_length=64)
    source_ip: str = ""
    username: str = ""
    path: str = ""
    user_agent: str = ""
    outcome: str = ""
    occurred_at: datetime | None = None
    raw: dict = {}


class SecurityEventBatch(BaseModel):
    events: list[SecurityEventIn] = Field(min_length=1, max_length=1000)


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    event_type: str
    source_ip: str
    username: str
    path: str
    outcome: str
    occurred_at: datetime


class DetectionRuleCreate(BaseModel):
    key: str = Field(min_length=1, max_length=128)
    name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    event_type: str = ""
    conditions: dict = {}
    threshold: int = Field(default=1, ge=1)
    window_seconds: int = Field(default=300, ge=1)
    group_by: list[str] = []
    mitre_technique_ids: list[str] = []
    references: list[str] = []
    enabled: bool = True


class DetectionRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: Severity | None = None
    conditions: dict | None = None
    threshold: int | None = Field(default=None, ge=1)
    window_seconds: int | None = Field(default=None, ge=1)
    group_by: list[str] | None = None
    mitre_technique_ids: list[str] | None = None
    enabled: bool | None = None


class DetectionRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    organization_id: int | None
    key: str
    name: str
    description: str
    severity: Severity
    event_type: str
    conditions: dict
    threshold: int
    window_seconds: int
    group_by: list
    mitre_technique_ids: list
    references: list
    enabled: bool
    version: int


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    state: AlertState | None = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    rule_id: int | None
    title: str
    severity: Severity
    state: AlertState
    status: AlertStatus
    entity: str
    event_count: int
    evidence: dict
    mitre_technique_ids: list
    risk_score: float
    first_seen: datetime
    last_seen: datetime


class MitreTechniqueOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    technique_id: str
    name: str
    tactic: str
    description: str
    url: str
