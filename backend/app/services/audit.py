"""Audit logging helper. Records security-sensitive actions; never secrets."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger, request_id_ctx
from app.models.governance import AuditLog

logger = get_logger("sentinelx.audit")

# Defensive denylist so a careless caller cannot persist secret-like keys.
_REDACT_KEYS = {"password", "token", "secret", "api_key", "authorization", "hashed_password"}


def _sanitize(meta: dict | None) -> dict:
    if not meta:
        return {}
    return {k: ("[REDACTED]" if k.lower() in _REDACT_KEYS else v) for k, v in meta.items()}


def record(
    db: Session,
    *,
    action: str,
    actor_id: int | None = None,
    organization_id: int | None = None,
    resource_type: str = "",
    resource_id: str | int = "",
    result: str = "success",
    ip: str = "",
    meta: dict | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        actor_id=actor_id,
        organization_id=organization_id,
        resource_type=resource_type,
        resource_id=str(resource_id),
        result=result,
        ip=ip,
        request_id=request_id_ctx.get(),
        meta=_sanitize(meta),
    )
    db.add(entry)
    if commit:
        db.commit()
    logger.info("audit action=%s resource=%s:%s result=%s", action, resource_type, resource_id, result)
    return entry
