"""Scan jobs and normalized findings."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, PKMixin, TimestampMixin, utcnow
from app.models.enums import (
    Confidence,
    FindingStatus,
    ScanStatus,
    ScanType,
    Severity,
)


class Scan(Base, PKMixin, TimestampMixin):
    __tablename__ = "scans"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.QUEUED, nullable=False, index=True
    )
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    target: Mapped[str] = mapped_column(String(1024), default="")

    # Cooperative-cancellation flag polled by the worker.
    cancel_requested: Mapped[bool] = mapped_column(default=False, nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
    stats: Mapped[dict] = mapped_column(JSON, default=dict)

    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base, PKMixin, TimestampMixin):
    __tablename__ = "findings"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Stable identity for de-duplication across repeated scans of the same asset.
    fingerprint: Mapped[str] = mapped_column(String(128), index=True, nullable=False)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(128), default="", index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False, index=True)
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence), default=Confidence.MEDIUM)
    detection_source: Mapped[str] = mapped_column(String(64), default="engine")

    evidence: Mapped[str] = mapped_column(Text, default="")
    parameter: Mapped[str] = mapped_column(String(255), default="")
    affected_component: Mapped[str] = mapped_column(String(255), default="")
    cve: Mapped[str] = mapped_column(String(64), default="")
    cwe: Mapped[str] = mapped_column(String(64), default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True
    )

    # Transparent, explainable risk (see services.risk_engine).
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_explanation: Mapped[dict] = mapped_column(JSON, default=dict)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan | None] = relationship(back_populates="findings")
