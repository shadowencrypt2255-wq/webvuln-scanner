"""Database initialization and idempotent reference-data seeding.

``init_db`` creates tables (used for local/dev/test when not running Alembic)
and seeds MITRE techniques and default global detection rules if absent.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, engine
from app.models import Base
from app.models.detection import DetectionRule, MitreTechnique
from app.seeds.mitre_data import MITRE_TECHNIQUES
from app.seeds.rules_data import DEFAULT_RULES


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def seed_reference_data(db: Session) -> None:
    for t in MITRE_TECHNIQUES:
        if not db.scalar(select(MitreTechnique).where(
                MitreTechnique.technique_id == t["technique_id"])):
            db.add(MitreTechnique(**t))

    for r in DEFAULT_RULES:
        exists = db.scalar(select(DetectionRule).where(
            DetectionRule.organization_id.is_(None), DetectionRule.key == r["key"]))
        if not exists:
            db.add(DetectionRule(organization_id=None, **r))
    db.commit()


def init_db() -> None:
    create_tables()
    db = SessionLocal()
    try:
        seed_reference_data(db)
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized and reference data seeded.")
