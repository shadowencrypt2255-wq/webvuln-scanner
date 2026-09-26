from datetime import UTC, datetime

from app.models.assets import Project
from app.models.detection import SecurityEvent
from app.models.enums import AlertState
from app.models.identity import Organization
from app.services import detection_engine


def _project(db) -> Project:
    org = Organization(name="Org", slug=f"org-{datetime.now().timestamp()}")
    db.add(org)
    db.flush()
    project = Project(organization_id=org.id, name="P")
    db.add(project)
    db.commit()
    return project


def _failed_login(project_id, ip="203.0.113.9"):
    return SecurityEvent(project_id=project_id, event_type="authentication",
                         source_ip=ip, username="admin", outcome="failure",
                         occurred_at=datetime.now(UTC))


def test_bruteforce_rule_fires_at_threshold(db):
    project = _project(db)
    for _ in range(9):  # threshold is 8
        db.add(_failed_login(project.id))
    db.commit()

    alerts = detection_engine.run_detection(db, project.id, project.organization_id,
                                            {"authentication"})
    keys = {a.dedup_key for a in alerts}
    assert any("auth.bruteforce" in k for k in keys)
    brute = next(a for a in alerts if "auth.bruteforce" in a.dedup_key)
    assert brute.state == AlertState.SUSPICIOUS
    assert brute.entity == "203.0.113.9"
    assert "T1110" in brute.mitre_technique_ids


def test_below_threshold_does_not_fire(db):
    project = _project(db)
    for _ in range(3):
        db.add(_failed_login(project.id))
    db.commit()
    alerts = detection_engine.run_detection(db, project.id, project.organization_id,
                                            {"authentication"})
    assert not any("auth.bruteforce" in a.dedup_key for a in alerts)


def test_repeated_run_updates_same_alert(db):
    project = _project(db)
    for _ in range(9):
        db.add(_failed_login(project.id))
    db.commit()
    first = detection_engine.run_detection(db, project.id, project.organization_id)
    count_after_first = len(first)
    # Running again should update, not duplicate, the alert.
    detection_engine.run_detection(db, project.id, project.organization_id)
    from app.models.detection import Alert
    from sqlalchemy import func, select
    total = db.scalar(select(func.count()).select_from(Alert).where(Alert.project_id == project.id))
    assert count_after_first >= 1
    assert total == count_after_first  # no duplicates on re-run
