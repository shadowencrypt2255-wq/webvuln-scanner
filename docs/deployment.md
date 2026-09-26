# Deployment

## Docker Compose (reference stack)

`docker-compose.yml` builds and runs five services: **db** (PostgreSQL 16), **redis**,
**backend** (FastAPI + Uvicorn), **worker** (Celery), and **frontend** (Next.js standalone).

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # put into SECRET_KEY
docker compose up --build -d
docker compose ps
```

- Backend: http://localhost:8000 (`/health`, `/ready`, `/docs`)
- Frontend: http://localhost:3000

The backend container runs migrations (`alembic upgrade head`) and seeds reference data on start
via `docker/entrypoint.sh`; the worker skips migrations (`RUN_MIGRATIONS=0`). Containers run as a
non-root user and expose health checks.

## Required configuration

| Variable | Notes |
|----------|-------|
| `SECRET_KEY` | **Required.** The app refuses to start in production without it. |
| `DATABASE_URL` | `postgresql+psycopg://…` in production. |
| `REDIS_URL` | Enables the real Celery broker/worker (async scans). |
| `CORS_ORIGINS` | JSON array of allowed frontend origins. |
| `ALLOW_PRIVATE_SCAN_TARGETS` | Keep `false` in production. |
| `NEXT_PUBLIC_API_BASE_URL` | Baked into the frontend at build time. |

## Production hardening checklist
- Terminate TLS at a reverse proxy; HSTS is emitted when `ENVIRONMENT=production`.
- Set strong `POSTGRES_PASSWORD` and a unique `SECRET_KEY`; store both in a secret manager.
- Restrict `CORS_ORIGINS` to your real frontend origin(s).
- Keep `ALLOW_PRIVATE_SCAN_TARGETS=false` unless running an isolated lab.
- Scale workers with `--concurrency`; put the API behind the proxy and enable request logging.
- Back up the Postgres volume; run `alembic upgrade head` on deploy.

## CI

`.github/workflows/ci.yml` runs on push/PR: ruff lint, scanner tests, backend tests, frontend
lint+build, and a backend Docker image build. CI fails if any step fails.
