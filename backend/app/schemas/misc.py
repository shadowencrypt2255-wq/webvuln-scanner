"""Audit, report, notification, AI, correlation, graph, and dashboard schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReportFormat, ReportStatus, ReportType


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    organization_id: int | None
    actor_id: int | None
    action: str
    resource_type: str
    resource_id: str
    result: str
    ip: str
    request_id: str
    meta: dict


class ReportCreate(BaseModel):
    report_type: ReportType
    fmt: ReportFormat


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_id: int
    report_type: ReportType
    fmt: ReportFormat
    status: ReportStatus
    created_at: datetime
    error: str


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    type: str
    title: str
    body: str
    link: str
    read: bool


class NotificationPrefOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    on_critical_finding: bool
    on_new_exposed_asset: bool
    on_scan_failure: bool
    on_important_alert: bool


class NotificationPrefUpdate(BaseModel):
    on_critical_finding: bool | None = None
    on_new_exposed_asset: bool | None = None
    on_scan_failure: bool | None = None
    on_important_alert: bool | None = None


class CorrelationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source_type: str
    source_id: int
    target_type: str
    target_id: int
    relation: str
    reason: str
    weight: float


class AiQuery(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    project_id: int | None = None


class AiAnswer(BaseModel):
    answer: str
    facts: list[str]
    provider: str
    disclaimer: str
    context_refs: dict


# --- Graph ---
class GraphNode(BaseModel):
    id: str
    kind: str
    label: str
    meta: dict = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    reason: str = ""


class GraphOut(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


# --- Dashboard ---
class SeverityBreakdown(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0


class DashboardOut(BaseModel):
    total_assets: int
    authorized_assets: int
    open_findings: int
    critical_findings: int
    high_findings: int
    active_alerts: int
    recent_scans: int
    findings_by_severity: SeverityBreakdown
    assets_by_type: dict[str, int]
    top_risk_findings: list
    generated_at: datetime
