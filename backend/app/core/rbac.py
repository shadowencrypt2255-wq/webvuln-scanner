"""Role-based access control: permission catalog and role->permission mapping.

Permissions are enforced on the backend (see ``app.api.deps``). The frontend
only *hides* controls; it is never the authority.
"""
from __future__ import annotations

from app.models.enums import Role

# --- Permission catalog ---
ORG_READ = "org.read"
ORG_MANAGE = "org.manage"
PROJECT_READ = "project.read"
PROJECT_MANAGE = "project.manage"
ASSET_READ = "asset.read"
ASSET_CREATE = "asset.create"
ASSET_UPDATE = "asset.update"
ASSET_DELETE = "asset.delete"
ASSET_AUTHORIZE = "asset.authorize"
SCAN_CREATE = "scan.create"
SCAN_READ = "scan.read"
SCAN_CANCEL = "scan.cancel"
FINDING_READ = "vulnerability.read"
FINDING_MANAGE = "vulnerability.manage"
EVENT_INGEST = "event.ingest"
EVENT_READ = "event.read"
ALERT_READ = "alert.read"
ALERT_MANAGE = "alert.manage"
RULE_READ = "detection_rule.read"
RULE_MANAGE = "detection_rule.manage"
CORRELATION_READ = "correlation.read"
REPORT_CREATE = "report.create"
REPORT_READ = "report.read"
AI_USE = "ai.use"
USER_MANAGE = "user.manage"
SETTINGS_MANAGE = "settings.manage"
AUDIT_READ = "audit.read"

ALL_PERMISSIONS: frozenset[str] = frozenset({
    ORG_READ, ORG_MANAGE, PROJECT_READ, PROJECT_MANAGE,
    ASSET_READ, ASSET_CREATE, ASSET_UPDATE, ASSET_DELETE, ASSET_AUTHORIZE,
    SCAN_CREATE, SCAN_READ, SCAN_CANCEL,
    FINDING_READ, FINDING_MANAGE,
    EVENT_INGEST, EVENT_READ, ALERT_READ, ALERT_MANAGE,
    RULE_READ, RULE_MANAGE, CORRELATION_READ,
    REPORT_CREATE, REPORT_READ, AI_USE,
    USER_MANAGE, SETTINGS_MANAGE, AUDIT_READ,
})

_READ_ONLY: frozenset[str] = frozenset({
    ORG_READ, PROJECT_READ, ASSET_READ, SCAN_READ, FINDING_READ,
    EVENT_READ, ALERT_READ, RULE_READ, CORRELATION_READ, REPORT_READ, AI_USE,
})

_ANALYST: frozenset[str] = _READ_ONLY | {
    PROJECT_MANAGE,
    ASSET_CREATE, ASSET_UPDATE, ASSET_DELETE, ASSET_AUTHORIZE,
    SCAN_CREATE, SCAN_CANCEL,
    FINDING_MANAGE,
    EVENT_INGEST, ALERT_MANAGE, RULE_MANAGE,
    REPORT_CREATE, AUDIT_READ,
}

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: ALL_PERMISSIONS,
    Role.SECURITY_ANALYST: frozenset(_ANALYST),
    Role.VIEWER: _READ_ONLY,
}


def permissions_for(role: Role) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def role_has_permission(role: Role, permission: str) -> bool:
    return permission in permissions_for(role)
