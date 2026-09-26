"""SQLAlchemy models for SentinelX.

Importing this package registers every model on the shared ``Base.metadata``
so Alembic autogeneration and ``Base.metadata.create_all`` see them all.
"""
from app.models.assets import Asset, AssetRelationship, Project
from app.models.base import Base
from app.models.correlation import Correlation, FindingTechnique
from app.models.detection import (
    Alert,
    DetectionRule,
    MitreTechnique,
    SecurityEvent,
)
from app.models.governance import (
    AiSession,
    AuditLog,
    Notification,
    NotificationPreference,
    Report,
)
from app.models.identity import Organization, OrganizationMembership, User
from app.models.scans import Finding, Scan

__all__ = [
    "Base",
    "User",
    "Organization",
    "OrganizationMembership",
    "Project",
    "Asset",
    "AssetRelationship",
    "Scan",
    "Finding",
    "SecurityEvent",
    "DetectionRule",
    "Alert",
    "MitreTechnique",
    "Correlation",
    "FindingTechnique",
    "AuditLog",
    "Report",
    "Notification",
    "NotificationPreference",
    "AiSession",
]
