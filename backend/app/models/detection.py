"""Threat detection: security events, detection rules, alerts, MITRE techniques."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, PKMixin, TimestampMixin, utcnow
from app.models.enums import AlertState, AlertStatus, Severity


class SecurityEvent(Base, PKMixin, TimestampMixin):
    """A single ingested security/log event (authentication, web access, etc.)."""

    __tablename__ = "security_events"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    username: Mapped[str] = mapped_column(String(255), default="", index=True)
    path: Mapped[str] = mapped_column(String(1024), default="")
    user_agent: Mapped[str] = mapped_column(String(512), default="")
    outcome: Mapped[str] = mapped_column(String(32), default="")  # success/failure/etc.
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class DetectionRule(Base, PKMixin, TimestampMixin):
    """A modular, versioned detection rule evaluated against security events."""

    __tablename__ = "detection_rules"

    # Global rules (organization_id NULL) or org-scoped custom rules.
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    key: Mapped[str] = mapped_column(String(128), index=True, nullable=False)  # e.g. auth.bruteforce
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    event_type: Mapped[str] = mapped_column(String(64), default="", index=True)
    # Structured, declarative conditions interpreted by the detection engine.
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    threshold: Mapped[int] = mapped_column(Integer, default=1)
    window_seconds: Mapped[int] = mapped_column(Integer, default=300)
    group_by: Mapped[list] = mapped_column(JSON, default=list)  # e.g. ["source_ip"]
    mitre_technique_ids: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1)

    alerts: Mapped[list[Alert]] = relationship(back_populates="rule")


class Alert(Base, PKMixin, TimestampMixin):
    __tablename__ = "alerts"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM, index=True)
    state: Mapped[AlertState] = mapped_column(Enum(AlertState), default=AlertState.OBSERVED)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus), default=AlertStatus.OPEN, index=True
    )
    # Grouping key so repeated matches update one alert instead of spamming.
    dedup_key: Mapped[str] = mapped_column(String(255), index=True, default="")
    entity: Mapped[str] = mapped_column(String(255), default="")  # e.g. the offending source_ip
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    mitre_technique_ids: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    rule: Mapped[DetectionRule | None] = relationship(back_populates="alerts")


class MitreTechnique(Base, PKMixin, TimestampMixin):
    """Reference data: a MITRE ATT&CK technique (seeded)."""

    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # e.g. T1110
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(512), default="")
