"""Bridges the scanner engine library to the database.

Runs an authorized scan, normalizes engine findings into the common Finding
schema, de-duplicates by fingerprint, computes explainable risk, attaches
POTENTIAL MITRE techniques, emits notifications for high-severity results, and
records audit + scan lifecycle state.
"""
from __future__ import annotations

import hashlib
import sys
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.netsafe import TargetNotAllowed, validate_scan_url
from app.models.assets import Asset
from app.models.correlation import FindingTechnique
from app.models.enums import (
    AuthorizationStatus,
    Confidence,
    ScanStatus,
    ScanType,
    Severity,
)
from app.models.governance import Notification
from app.models.scans import Finding, Scan
from app.services import audit
from app.services.finding_catalog import metadata_for
from app.services.risk_engine import RiskInputs, compute_risk

# Make the top-level ``scanner`` package importable regardless of CWD.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scanner.engine import ScanCancelled, ScanEngine, ScanTimeout  # noqa: E402
from scanner.findings import Finding as EngineFinding  # noqa: E402

logger = get_logger("sentinelx.scan")


def _engine_flags(scan_type: ScanType) -> dict:
    return {
        ScanType.DISCOVERY: dict(run_web_vuln=False, run_auth=False, run_headers=False),
        ScanType.TLS_HTTP: dict(run_web_vuln=False, run_auth=True, run_headers=True),
        ScanType.WEB_VULN: dict(run_web_vuln=True, run_auth=True, run_headers=False),
        ScanType.FULL: dict(run_web_vuln=True, run_auth=True, run_headers=True),
    }[scan_type]


def _fingerprint(asset_id: int, ef: EngineFinding) -> str:
    path = urllib.parse.urlparse(ef.url).path or "/"
    header = str(ef.extra.get("header", ""))
    raw = f"{asset_id}|{ef.category}|{path}|{ef.parameter}|{header}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _to_severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


def _title(ef: EngineFinding) -> str:
    base = ef.category
    if ef.parameter:
        return f"{base} in parameter '{ef.parameter}'"
    header = ef.extra.get("header")
    if header:
        return f"{base}: {header}"
    return base


def run_scan(db: Session, scan_id: int) -> Scan:
    """Execute a queued scan. Idempotent transitions; always leaves a terminal state."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"scan {scan_id} not found")
    if scan.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        return scan

    asset = db.get(Asset, scan.asset_id)
    if asset is None:
        _finish(db, scan, ScanStatus.FAILED, error="asset no longer exists")
        return scan

    # Authorization gate — refuse to scan anything not explicitly authorized.
    if asset.authorization_status != AuthorizationStatus.AUTHORIZED:
        _finish(db, scan, ScanStatus.FAILED,
                error="asset is not AUTHORIZED for scanning")
        audit.record(db, action="scan.blocked_unauthorized", actor_id=scan.created_by_id,
                     organization_id=None, resource_type="scan", resource_id=scan.id,
                     result="blocked", meta={"asset_id": asset.id})
        return scan

    target = scan.target or asset.value
    try:
        target = validate_scan_url(target)
    except TargetNotAllowed as exc:
        _finish(db, scan, ScanStatus.FAILED, error=f"target rejected: {exc}")
        return scan

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(UTC)
    db.commit()

    cfg = scan.config or {}
    flags = _engine_flags(scan.scan_type)

    def cancelled() -> bool:
        db.refresh(scan, attribute_names=["cancel_requested"])
        return bool(scan.cancel_requested)

    engine = ScanEngine(
        target_url=target,
        max_pages=int(cfg.get("max_pages", settings.scan_max_pages)),
        threads=settings.scan_max_concurrency,
        requests_per_second=settings.scan_requests_per_second,
        timeout=settings.scan_timeout_seconds,
        skip_auth_bruteforce=bool(cfg.get("skip_auth_bruteforce", True)),
        cancel_check=cancelled,
        deadline_seconds=settings.scan_hard_deadline_seconds,
        **flags,
    )

    try:
        crawl_result, engine_findings = engine.run()
    except ScanCancelled:
        _finish(db, scan, ScanStatus.CANCELLED, error="cancelled by user")
        return scan
    except ScanTimeout:
        _finish(db, scan, ScanStatus.TIMEOUT, error="hard deadline exceeded")
        return scan
    except Exception as exc:  # engine/network failure — captured, never hidden
        logger.exception("scan %s failed", scan_id)
        _finish(db, scan, ScanStatus.FAILED, error=f"engine error: {exc}")
        return scan

    new_high = _persist_findings(db, scan, asset, engine_findings)

    scan.stats = {
        "pages_crawled": len(crawl_result.pages),
        "forms_found": len(crawl_result.forms),
        "findings": len(engine_findings),
    }
    _finish(db, scan, ScanStatus.COMPLETED)
    asset.last_seen = datetime.now(UTC)
    db.commit()

    if new_high:
        _notify_high(db, asset.project_id, new_high)

    audit.record(db, action="scan.completed", actor_id=scan.created_by_id,
                 resource_type="scan", resource_id=scan.id,
                 meta={"asset_id": asset.id, "findings": len(engine_findings)})
    return scan


def _persist_findings(db: Session, scan: Scan, asset: Asset,
                      engine_findings: list[EngineFinding]) -> list[Finding]:
    now = datetime.now(UTC)
    new_high: list[Finding] = []
    # Track (finding_id, technique_id) added this run — autoflush is off, so a
    # pending row is not visible to the dedup query until flush/commit.
    seen_techniques: set[tuple[int, str]] = set()

    for ef in engine_findings:
        fp = _fingerprint(asset.id, ef)
        meta = metadata_for(ef.category)
        severity = _to_severity(ef.severity.value if hasattr(ef.severity, "value") else str(ef.severity))
        confidence = meta.get("confidence", Confidence.MEDIUM)

        existing = db.scalar(
            select(Finding).where(Finding.project_id == asset.project_id,
                                   Finding.fingerprint == fp)
        )
        risk_inputs = RiskInputs(
            severity=severity, confidence=confidence,
            asset_criticality=asset.criticality, environment=asset.environment,
            asset_type=asset.type.value,
            first_seen=(existing.first_seen if existing else now),
        )
        score, explanation = compute_risk(risk_inputs)

        if existing:
            existing.last_seen = now
            existing.scan_id = scan.id
            existing.evidence = ef.evidence
            existing.severity = severity
            existing.risk_score = score
            existing.risk_explanation = explanation
            finding = existing
        else:
            finding = Finding(
                project_id=asset.project_id,
                asset_id=asset.id,
                scan_id=scan.id,
                fingerprint=fp,
                title=_title(ef),
                description=ef.description,
                category=ef.category,
                severity=severity,
                confidence=confidence,
                detection_source="engine",
                evidence=ef.evidence,
                parameter=ef.parameter,
                affected_component=str(ef.extra.get("header", "")),
                cwe=meta.get("cwe", ""),
                references=meta.get("references", []),
                remediation=meta.get("remediation", ""),
                risk_score=score,
                risk_explanation=explanation,
                first_seen=now,
                last_seen=now,
            )
            db.add(finding)
            db.flush()
            if severity in (Severity.HIGH, Severity.CRITICAL):
                new_high.append(finding)

        # Attach POTENTIAL MITRE techniques (idempotent within run and in DB).
        for tech_id in meta.get("mitre", []):
            pair = (finding.id, tech_id)
            if pair in seen_techniques:
                continue
            exists = db.scalar(
                select(FindingTechnique).where(
                    FindingTechnique.finding_id == finding.id,
                    FindingTechnique.technique_id == tech_id,
                )
            )
            if not exists:
                db.add(FindingTechnique(
                    finding_id=finding.id, technique_id=tech_id,
                    relationship_kind="POTENTIAL", confidence=confidence.value,
                    evidence=f"Derived from finding category '{ef.category}'.",
                ))
            seen_techniques.add(pair)

    db.commit()
    return new_high


def _notify_high(db: Session, project_id: int, findings: list[Finding]) -> None:
    from app.models.assets import Project
    project = db.get(Project, project_id)
    if project is None:
        return
    for f in findings:
        db.add(Notification(
            organization_id=project.organization_id,
            type="critical_finding" if f.severity == Severity.CRITICAL else "high_finding",
            title=f"{f.severity.value} finding: {f.title}",
            body=f.description[:500],
            link=f"/findings/{f.id}",
        ))
    db.commit()


def _finish(db: Session, scan: Scan, status: ScanStatus, error: str = "") -> None:
    scan.status = status
    scan.finished_at = datetime.now(UTC)
    if error:
        scan.error = error
    db.commit()
