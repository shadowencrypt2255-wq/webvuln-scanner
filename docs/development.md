# Development

## Prerequisites
- Python 3.12, Node 20. (Docker optional.)

## Backend

```bash
python -m venv .venv
. .venv/Scripts/activate            # Windows;  source .venv/bin/activate elsewhere
pip install -r backend/requirements-dev.txt

cd backend
python -m app.db_init               # SQLite schema + reference data
python -m scripts.seed_demo         # optional demo data
uvicorn app.main:app --reload
```

Environment variables come from a `.env` at the repo root (see `.env.example`). In development
`SECRET_KEY` is auto-generated and the database defaults to SQLite, so no external services are
required. Celery runs eagerly when `REDIS_URL` is empty.

### Migrations

```bash
cd backend
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

`app.db_init` uses `create_all` for quick local setup; production uses Alembic (`alembic upgrade
head`, run automatically by the Docker entrypoint).

### Tests & lint

```bash
pytest tests -q                                             # scanner engine
cd backend && ALLOW_PRIVATE_SCAN_TARGETS=true SECRET_KEY=x pytest -q   # backend
ruff check backend scanner
```

The backend suite includes a live end-to-end scan against the bundled testbed (started
in-process), plus unit (risk/detection/rbac/SSRF), integration (auth/RBAC/scan lifecycle) and
security (cross-tenant isolation, authorization gate) tests.

## Frontend

```bash
cd frontend
npm install
npm run dev        # http://localhost:3000  (talks to NEXT_PUBLIC_API_BASE_URL)
npm run lint
npm run build
```

## Layout tips
- Engine checks live in `scanner/`; add a new check module and wire it into `scanner/engine.py`
  and `backend/app/services/finding_catalog.py` (CWE/remediation/MITRE metadata).
- New endpoints go under `backend/app/api/v1/`, included via `router.py`, and must enforce
  permissions through `app/api/deps.py`.
