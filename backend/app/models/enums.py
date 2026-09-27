"""Enumerations used across the domain model.

Stored as their string ``value`` in the database (portable across SQLite and
PostgreSQL) via SQLAlchemy's native ``Enum`` type.
"""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    VIEWER = "VIEWER"


class AssetType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    HOST = "HOST"
    URL = "URL"
    SERVICE = "SERVICE"
    CERTIFICATE = "CERTIFICATE"
    API_ENDPOINT = "API_ENDPOINT"
    CLOUD = "CLOUD"


class AuthorizationStatus(str, Enum):
    UNAUTHORIZED = "UNAUTHORIZED"
    AUTHORIZED = "AUTHORIZED"
    REVOKED = "REVOKED"


class AssetLifecycle(str, Enum):
    DISCOVERED = "DISCOVERED"
    VERIFIED = "VERIFIED"
    AUTHORIZED = "AUTHORIZED"
    MONITORED = "MONITORED"
    RETIRED = "RETIRED"


class Criticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanType(str, Enum):
    DISCOVERY = "DISCOVERY"          # crawl + attack-surface inventory
    WEB_VULN = "WEB_VULN"            # authorized web checks (SQLi/XSS/auth/headers)
    TLS_HTTP = "TLS_HTTP"            # passive HTTP security-header / TLS analysis
    FULL = "FULL"                    # discovery + web vuln + passive


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    IN_PROGRESS = "IN_PROGRESS"
    MITIGATED = "MITIGATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class AlertState(str, Enum):
    OBSERVED = "OBSERVED"
    SUSPICIOUS = "SUSPICIOUS"
    CORRELATED = "CORRELATED"
    CONFIRMED = "CONFIRMED"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class ReportType(str, Enum):
    EXECUTIVE = "EXECUTIVE"
    TECHNICAL = "TECHNICAL"


class ReportFormat(str, Enum):
    PDF = "PDF"
    CSV = "CSV"
    JSON = "JSON"


class ReportStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    FAILED = "FAILED"
