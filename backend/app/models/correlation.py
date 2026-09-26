"""Correlation edges linking domain entities, and finding<->technique mapping."""
from __future__ import annotations

from sqlalchemy import JSON, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, PKMixin, TimestampMixin


class Correlation(Base, PKMixin, TimestampMixin):
    """A typed, explained relationship between two security entities.

    Nodes are referenced by (type, id) rather than hard FKs so any pair of
    entity kinds can be linked. Every correlation stores a human-readable
    ``reason`` — relationships are never created without justification.
    """

    __tablename__ = "correlations"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)  # asset/finding/alert/event
    source_id: Mapped[int] = mapped_column(Integer, nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class FindingTechnique(Base, PKMixin, TimestampMixin):
    """Maps a finding to a MITRE technique, flagged POTENTIAL vs OBSERVED."""

    __tablename__ = "finding_techniques"
    __table_args__ = (
        UniqueConstraint("finding_id", "technique_id", name="uq_finding_technique"),
    )

    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String(16), nullable=False)  # T-code
    relationship_kind: Mapped[str] = mapped_column(String(16), default="POTENTIAL")  # or OBSERVED
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    evidence: Mapped[str] = mapped_column(Text, default="")
