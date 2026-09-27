"""Scan and finding schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    Confidence,
    FindingStatus,
    ScanStatus,
    ScanType,
    Severity,
)


class ScanCreate(BaseModel):
    asset_id: int
    scan_type: ScanType = ScanType.FULL
    max_pages: int | None = Field(default=None, ge=1, le=1000)
    skip_auth_bruteforce: bool = True


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    asset_id: int
    scan_type: ScanType
    status: ScanStatus
    target: str
    config: dict
    cancel_requested: bool
    started_at: datetime | None
    finished_at: datetime | None
    error: str
    stats: dict
    created_at: datetime


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    remediation: str | None = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    asset_id: int
    scan_id: int | None
    fingerprint: str
    title: str
    description: str
    category: str
    severity: Severity
    confidence: Confidence
    detection_source: str
    evidence: str
    parameter: str
    affected_component: str
    cve: str
    cwe: str
    cvss_score: float | None
    references: list
    remediation: str
    status: FindingStatus
    risk_score: float
    risk_explanation: dict
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
