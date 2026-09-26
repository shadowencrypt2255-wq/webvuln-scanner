# SentinelX

**AI-assisted attack surface & threat detection platform — for authorized security assessments only.**

SentinelX is a modular security platform that takes an authorized asset through the full
lifecycle: **discovery → assessment → detection → correlation → risk → remediation → reporting.**
It combines a Python/FastAPI backend, a reusable scanning engine, a threat-detection and
correlation engine, an explainable risk model, a tool-bounded AI analyst, and a Next.js
dashboard.

> ⚠️ **Authorized use only.** SentinelX sends real requests and attack payloads to targets.
> It refuses to scan any asset that has not been explicitly marked **AUTHORIZED**, and (outside
> an opt-in local-lab mode) refuses targets that resolve to private/loopback addresses. Only
> scan systems you own or are explicitly authorized to test. See [SECURITY.md](SECURITY.md).

---

## Features

- **Authentication** — registration, login, refresh tokens, Argon2id password hashing,
  account lockout, and login rate limiting.
- **RBAC & multi-tenancy** — organizations → projects → assets → scans → findings → alerts →
  reports, with `ADMIN` / `SECURITY_ANALYST` / `VIEWER` roles enforced **server-side**. Users
  cannot see or touch another organization's data (404, not 403, to avoid leaking existence).
- **Authorized asset inventory** — typed assets with an authorization lifecycle; scanning is
  gated on `AUTHORIZED` status plus SSRF-safe target validation.
- **Scan engine** — same-origin crawler, error/time-based SQL injection, reflected XSS,
  broken-authentication, and passive HTTP security-header checks; rate-limited, cancellable,
  with a hard deadline. Optional OWASP ZAP integration.
- **Findings & explainable risk** — normalized findings de-duplicated by fingerprint, each with
  a transparent `risk_score` = weighted sum of severity, asset criticality, exposure, confidence
  and age (every contribution stored and shown).
- **Threat detection** — ingest structured security events; declarative, versioned detection
  rules raise de-duplicated alerts (brute force, password spray, port-scan, etc.).
- **MITRE ATT&CK** — findings map to **POTENTIAL** techniques; detections carry **OBSERVED**
  techniques. The two are never conflated.
- **Correlation engine** — explains *why* entities are related (e.g. a finding's potential
  technique matching an alert's observed technique elevates the alert to `CORRELATED`).
- **Security graph** — derived from the relational model (no graph DB required).
- **AI Security Analyst** — read-only, tool-bounded, separates **facts** from **AI analysis**;
  works deterministically offline and can optionally call an LLM with prompt-injection defenses.
- **Reporting** — executive & technical reports as PDF / CSV / JSON from real data.
- **Audit logging** of security-sensitive actions (never secrets).

## Architecture

```
webvuln-scanner/            (SentinelX monorepo)
├── scanner/                # Discovery / vulnerability engine library (crawler, sqli, xss, auth, headers, zap)
├── testbed/                # Deliberately-vulnerable Flask app for the local lab
├── backend/
│   ├── app/
│   │   ├── core/           # config, db, security (Argon2/JWT), rbac, netsafe (SSRF), logging, rate limit
│   │   ├── models/         # SQLAlchemy models (19 tables)
│   │   ├── schemas/        # Pydantic request/response models
│   │   ├── services/       # risk, detection, correlation, scan_runner, graph, report, ai analyst
│   │   ├── api/v1/         # versioned REST API
│   │   └── worker/         # Celery app + tasks (eager when no Redis)
│   ├── alembic/            # migrations
│   └── tests/              # unit / integration / security
├── frontend/               # Next.js + TypeScript + Tailwind dashboard
├── docker/                 # backend & frontend Dockerfiles, entrypoint
├── docker-compose.yml      # full stack: db, redis, backend, worker, frontend
└── docs/                   # architecture, security, api, development, deployment
```

**Stack:** FastAPI · SQLAlchemy 2 · Pydantic v2 · Alembic · Celery/Redis · PostgreSQL (SQLite
for local dev/test) · Next.js 14 · Recharts · Docker · GitHub Actions.

## Quick start (Docker)

```bash
cp .env.example .env
# set a strong SECRET_KEY:  python -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose up --build
```

- API: http://localhost:8000  (docs at `/docs`)
- Frontend: http://localhost:3000

## Quick start (local, no Docker)

Requires Python 3.12 and Node 20.

```bash
# Backend
python -m venv .venv && . .venv/Scripts/activate   # (Windows) or: source .venv/bin/activate
pip install -r backend/requirements-dev.txt

cd backend
python -m app.db_init            # create SQLite schema + seed reference data
python -m scripts.seed_demo      # optional: demo user, org, project, authorized lab asset
uvicorn app.main:app --reload    # http://localhost:8000
```

```bash
# Frontend (separate terminal)
cd frontend
npm install
npm run dev                      # http://localhost:3000
```

Demo login (after `seed_demo`): **demo@sentinelx.io / SentinelX-demo-1234**

## Local security lab

The bundled Flask testbed is deliberately vulnerable and is only meant to be scanned locally:

```bash
python testbed/vulnerable_app.py         # serves http://127.0.0.1:5000
```

Set `ALLOW_PRIVATE_SCAN_TARGETS=true` to permit scanning loopback targets, then run a `FULL`
scan against the authorized testbed asset from the UI or API. It surfaces SQL injection, reflected
XSS, broken authentication, and missing security headers.

## Testing

```bash
# Scanner engine unit tests
pytest tests -q

# Backend unit + integration + security tests (incl. a live scan against the testbed)
cd backend
ALLOW_PRIVATE_SCAN_TARGETS=true SECRET_KEY=test-key pytest -q

# Lint
ruff check backend scanner

# Frontend
cd frontend && npm run lint && npm run build
```

## Documentation

- [docs/architecture.md](docs/architecture.md) — components, data model, request flow
- [docs/security.md](docs/security.md) — threat model & controls
- [docs/api.md](docs/api.md) — REST API overview
- [docs/development.md](docs/development.md) — local dev workflow
- [docs/deployment.md](docs/deployment.md) — production deployment
- [SECURITY.md](SECURITY.md) — authorized-use policy & vulnerability reporting

## Roadmap

See the "Known limitations" section of the final audit in [docs/AUDIT.md](docs/AUDIT.md).

## License

[MIT](LICENSE). Provided for authorized security testing and education only; the authors are
not responsible for misuse.
