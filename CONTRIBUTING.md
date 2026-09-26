# Contributing to SentinelX

Thanks for your interest! SentinelX is a defensive security platform for authorized assessments.
Contributions that add offensive capability intended for unauthorized use will not be accepted.

## Development setup

See [docs/development.md](docs/development.md). In short:

```bash
python -m venv .venv && . .venv/Scripts/activate
pip install -r backend/requirements-dev.txt
cd frontend && npm install
```

## Before opening a PR

Run the full local check suite:

```bash
ruff check backend scanner
pytest tests -q
cd backend && ALLOW_PRIVATE_SCAN_TARGETS=true SECRET_KEY=test-key pytest -q
cd ../frontend && npm run lint && npm run build
```

CI runs the same checks (see `.github/workflows/ci.yml`) and must pass.

## Guidelines

- **No secrets in code.** Use environment variables and update `.env.example`.
- **Keep the two-layer scan authorization intact.** Never remove the `AUTHORIZED` gate or the
  SSRF guard; features must not enable scanning of unauthorized or private targets by default.
- **Enforce authorization on the backend.** The frontend may hide controls, but every endpoint
  must check permissions and tenant boundaries.
- **No fabricated data.** Dashboard/report numbers must come from the database.
- **Tests required** for new engine logic, endpoints (including an authorization test), and bug
  fixes. Add a migration for any model change (`alembic revision --autogenerate`).
- **Style:** `ruff` for Python; the existing component patterns for the frontend. Keep modules
  small and typed.

## Commit / PR

- Write clear, descriptive commits.
- Describe the change, the threat/UX implications, and how you tested it in the PR body.
