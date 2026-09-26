"""Pytest bootstrap: configure a test environment before importing the app.

A file-backed SQLite database is used (not in-memory) so that the eager Celery
worker's own session sees rows committed by the request session.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# --- Paths: make ``app`` and the top-level ``scanner`` importable ---
_BACKEND = Path(__file__).resolve().parent
_REPO_ROOT = _BACKEND.parent
for p in (str(_BACKEND), str(_REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

# --- Test environment (must be set before importing app.core.config) ---
_DB_FILE = Path(tempfile.gettempdir()) / "sentinelx_test.db"
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("DATABASE_URL", f"sqlite+pysqlite:///{_DB_FILE.as_posix()}")
os.environ.setdefault("ALLOW_PRIVATE_SCAN_TARGETS", "true")

import pytest  # noqa: E402
from app.core.database import SessionLocal, engine  # noqa: E402
from app.db_init import seed_reference_data  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_reference_data(db)
    finally:
        db.close()
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def register():
    """Return a helper that registers a user+org and yields an authed context."""
    def _register(client: TestClient, email: str, org: str = "Acme Security",
                  password: str = "correct horse battery"):
        resp = client.post("/api/v1/auth/register", json={
            "email": email, "password": password, "full_name": email.split("@")[0],
            "organization_name": org,
        })
        assert resp.status_code == 201, resp.text
        tokens = resp.json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        me = client.get("/api/v1/auth/me", headers=headers).json()
        org_id = me["organizations"][0]["id"]
        return {"headers": headers, "tokens": tokens, "org_id": org_id, "me": me}
    return _register
