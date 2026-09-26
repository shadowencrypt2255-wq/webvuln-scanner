# SentinelX — Implementation Audit

Honest status of what was built, tested, and what remains. **Not** claimed production-ready.

## Architecture implemented
- Monorepo: reusable `scanner/` engine library, FastAPI `backend/`, Next.js `frontend/`,
  `docker/` + `docker-compose.yml`, `docs/`, CI.
- 19-table normalized schema with Alembic migrations; SQLite for dev/test, PostgreSQL for prod.
- Celery worker (eager in-process without Redis; broker-backed with Redis).

## Security controls
- Argon2id hashing, JWT access/refresh, account lockout, login rate limiting.
- Server-side RBAC (`ADMIN`/`SECURITY_ANALYST`/`VIEWER`) + multi-tenant isolation (404 on
  cross-tenant access).
- Two-layer scan safety: `AUTHORIZED` asset gate + SSRF guard; rate/concurrency/timeout/deadline
  limits; cooperative cancellation.
- Security headers, restricted CORS, structured errors (no stack traces to clients), audit logging
  with secret redaction, tool-bounded read-only AI with prompt-injection defenses.
- Threat model documented in [security.md](security.md).

## Functionality (implemented & working)
Auth · RBAC · multi-tenancy · asset inventory + authorization lifecycle · scan lifecycle
(crawl + SQLi/XSS/broken-auth/security-headers) · normalized findings with de-dup · explainable
risk scoring · threat-detection rules → alerts · MITRE mapping (POTENTIAL vs OBSERVED) ·
correlation engine · security graph · AI analyst · executive/technical reports (PDF/CSV/JSON) ·
notifications · audit log · search/filtering/pagination.

## Testing
- **31 automated tests pass** (26 backend + 5 scanner engine).
  - Unit: risk engine, detection engine, RBAC, SSRF guard.
  - Integration: register/login/`me`, lockout, RBAC, and a **live end-to-end scan** against the
    bundled testbed (register → authorize asset → FULL scan → findings → dashboard → report).
  - Security: cross-tenant IDOR (404), scan authorization gate (403), unauthenticated (401).
- Lint: `ruff check backend scanner` clean.
- Frontend: `next build` succeeds (19 routes); `next lint` clean.
- **Manually verified live** through the real UI: login, dashboard (real metrics + fired detection
  alerts), a UI-driven scan producing 26 findings, finding detail with the transparent risk
  breakdown + MITRE technique, and the AI analyst separating facts from analysis.

## UI/UX
- Consistent dark design system, responsive layout (sidebar collapses on mobile), loading /
  empty / error / permission states, accessible form labels, Recharts visualizations.
- Pages: login, register, dashboard, assets, scans (+detail), findings (+detail), alerts, rules,
  MITRE, graph, reports, audit, AI analyst, settings, admin.

## DevOps
- Dockerfiles (non-root, health checks) + compose (db/redis/backend/worker/frontend).
- GitHub Actions: lint → scanner tests → backend tests → frontend build → docker build.
- `.env.example`, `.gitignore`, migrations, entrypoint that migrates + seeds reference data.

## Documentation
README, SECURITY.md, CONTRIBUTING.md, LICENSE (MIT), and docs/ (architecture, security, api,
development, deployment, this audit).

## Known limitations (honest)
- **Not load-tested or pen-tested**; treat as a strong portfolio/reference project, not a
  battle-hardened production deployment.
- **Docker Compose stack was authored but not built/run here** (no Docker on the build machine).
  The backend + frontend were built and run natively and verified end-to-end; the compose/CI paths
  are written to spec but should be validated in an environment with Docker.
- **JWT logout is client-side** (token discard); there is no server-side refresh-token denylist.
- **Password reset / email verification** are modelled (token flows) but no email delivery channel
  is wired.
- **The LLM path of the AI analyst is off by default and untested** (no API key here); the
  deterministic analyst is the tested default.
- **Frontend depth:** core operator flows are complete; some management surfaces (e.g. editing
  detection rules, per-finding technique editing, notification center UI) are read-only or
  API-only.
- **CVE correlation** is via CWE/category metadata and references, not a live CVE/NVD feed lookup.
- Detection rules cover common patterns; Sigma/YARA import is future work.
- The scanner is intentionally scoped to safe, authorized checks; it is not a replacement for a
  full DAST product.
