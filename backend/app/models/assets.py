"""Projects, authorized assets, and asset relationships (attack surface)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, PKMixin, TimestampMixin, utcnow
from app.models.enums import (
    AssetLifecycle,
    AssetType,
    AuthorizationStatus,
    Criticality,
)


class Project(Base, PKMixin, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_project_org_name"),)

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")

    organization: Mapped[Organization] = relationship(back_populates="projects")  # noqa: F821
    assets: Mapped[list[Asset]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Asset(Base, PKMixin, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("project_id", "type", "value", name="uq_asset_project_type_value"),
    )

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255), default="")
    type: Mapped[AssetType] = mapped_column(Enum(AssetType), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)

    authorization_status: Mapped[AuthorizationStatus] = mapped_column(
        Enum(AuthorizationStatus), default=AuthorizationStatus.UNAUTHORIZED, nullable=False, index=True
    )
    # Free-form authorization note / reference (e.g. engagement id, ownership proof).
    authorization_note: Mapped[str] = mapped_column(Text, default="")
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    authorized_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    lifecycle: Mapped[AssetLifecycle] = mapped_column(
        Enum(AssetLifecycle), default=AssetLifecycle.DISCOVERED, nullable=False
    )
    criticality: Mapped[Criticality] = mapped_column(
        Enum(Criticality), default=Criticality.MEDIUM, nullable=False
    )
    environment: Mapped[str] = mapped_column(String(64), default="production")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    discovery_source: Mapped[str] = mapped_column(String(128), default="manual")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    project: Mapped[Project] = relationship(back_populates="assets")


class AssetRelationship(Base, PKMixin, TimestampMixin):
    """Directed edge between two assets (e.g. DOMAIN -> resolves_to -> IP)."""

    __tablename__ = "asset_relationships"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    source_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    target_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    relation: Mapped[str] = mapped_column(String(64), nullable=False)  # resolves_to, hosts, exposes
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
