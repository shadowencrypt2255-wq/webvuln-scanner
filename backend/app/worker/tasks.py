"""Background tasks: scan execution, detection, correlation, reporting."""
from __future__ import annotations

from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.worker.celery_app import celery_app

logger = get_logger("sentinelx.worker")


@celery_app.task(name="scan.run", bind=True, max_retries=0)
def run_scan_task(self, scan_id: int) -> dict:  # noqa: ANN001
    from app.services import correlation_engine, scan_runner

    db = SessionLocal()
    try:
        scan = scan_runner.run_scan(db, scan_id)
        # Recompute correlations for the project after new findings land.
        try:
            correlation_engine.build_correlations(db, scan.project_id)
        except Exception:  # noqa: BLE001
            logger.exception("correlation build failed for scan %s", scan_id)
        return {"scan_id": scan_id, "status": scan.status.value}
    finally:
        db.close()


@celery_app.task(name="report.generate", bind=True, max_retries=0)
def generate_report_task(self, report_id: int) -> dict:  # noqa: ANN001
    from app.services import report_engine

    db = SessionLocal()
    try:
        report = report_engine.generate_report(db, report_id)
        return {"report_id": report_id, "status": report.status.value}
    finally:
        db.close()


def enqueue_scan(scan_id: int) -> None:
    run_scan_task.delay(scan_id)


def enqueue_report(report_id: int) -> None:
    generate_report_task.delay(report_id)
