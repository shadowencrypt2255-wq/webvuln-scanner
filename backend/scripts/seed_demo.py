"""Seed a local demo environment: an admin user, an organization, a project, an
authorized lab asset (the bundled testbed), and synthetic security events that
trigger the brute-force detection rule.

Idempotent: safe to run repeatedly. Intended for LOCAL DEMO / LAB use only.

Usage (from backend/):
    python -m scripts.seed_demo
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import SessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db_init import init_db  # noqa: E402
from app.models.assets import Asset, Project  # noqa: E402
from app.models.detection import SecurityEvent  # noqa: E402
from app.models.enums import (  # noqa: E402
    AssetLifecycle,
    AssetType,
    AuthorizationStatus,
    Criticality,
    Role,
)
from app.models.identity import Organization, OrganizationMembership, User  # noqa: E402
from app.services import correlation_engine, detection_engine  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

DEMO_EMAIL = "demo@sentinelx.io"
DEMO_PASSWORD = "SentinelX-demo-1234"  # local demo credential only
TESTBED_URL = "http://127.0.0.1:5000/"


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        user = db.scalar(select(User).where(User.email == DEMO_EMAIL))
        if user is None:
            user = User(email=DEMO_EMAIL, hashed_password=hash_password(DEMO_PASSWORD),
                        full_name="Demo Analyst", is_superuser=True)
            db.add(user)
            db.flush()

        org = db.scalar(select(Organization).where(Organization.slug == "demo-security"))
        if org is None:
            org = Organization(name="Demo Security", slug="demo-security")
            db.add(org)
            db.flush()
            db.add(OrganizationMembership(user_id=user.id, organization_id=org.id, role=Role.ADMIN))

        project = db.scalar(select(Project).where(Project.organization_id == org.id,
                                                  Project.name == "Lab"))
        if project is None:
            project = Project(organization_id=org.id, name="Lab",
                              description="Local security lab against the bundled testbed.")
            db.add(project)
            db.flush()

        asset = db.scalar(select(Asset).where(Asset.project_id == project.id,
                                              Asset.value == TESTBED_URL))
        if asset is None:
            asset = Asset(
                project_id=project.id, name="Local testbed", type=AssetType.URL,
                value=TESTBED_URL, authorization_status=AuthorizationStatus.AUTHORIZED,
                authorization_note="Owned local lab target.",
                authorized_at=datetime.now(UTC), authorized_by_id=user.id,
                lifecycle=AssetLifecycle.AUTHORIZED, criticality=Criticality.HIGH,
                environment="test", discovery_source="seed",
            )
            db.add(asset)
            db.flush()

        # Synthetic brute-force events (only if none exist yet).
        existing = db.scalar(select(func.count()).select_from(SecurityEvent)
                             .where(SecurityEvent.project_id == project.id))
        if not existing:
            now = datetime.now(UTC)
            for i in range(12):
                db.add(SecurityEvent(
                    project_id=project.id, event_type="authentication",
                    source_ip="203.0.113.10", username=f"user{i % 3}", outcome="failure",
                    path="/login", occurred_at=now - timedelta(seconds=i * 5),
                ))
        db.commit()

        detection_engine.run_detection(db, project.id, org.id, {"authentication"})
        correlation_engine.build_correlations(db, project.id)
        db.commit()

        print("Demo environment ready.")
        print(f"  Login: {DEMO_EMAIL} / {DEMO_PASSWORD}")
        print(f"  Organization: {org.name} (id={org.id})  Project: {project.name} (id={project.id})")
        print(f"  Authorized asset: {asset.value} (id={asset.id})")
        print("  Start the testbed (python testbed/vulnerable_app.py), set "
              "ALLOW_PRIVATE_SCAN_TARGETS=true, then run a scan from the UI/API.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
