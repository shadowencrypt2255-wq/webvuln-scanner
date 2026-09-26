# Architecture

## Overview

SentinelX is a modular monorepo:

- **`scanner/`** — a standalone, importable engine library (crawler + SQLi/XSS/broken-auth/header
  checks + optional ZAP). It has no knowledge of the database or web app and is unit-tested on its
  own.
- **`backend/`** — a FastAPI application that wraps the engine with identity, tenancy, persistence,
  the analysis engines, and a REST API. Background work runs through Celery.
- **`frontend/`** — a Next.js dashboard that talks to the REST API.

## Request / scan flow

```
Client → FastAPI (authn + RBAC + tenant scope)
  POST /projects/{id}/scans
    → assert asset is AUTHORIZED
    → create Scan(QUEUED) → enqueue Celery task
      worker: scan_runner.run_scan
        → netsafe.validate_scan_url (SSRF guard)
        → scanner.ScanEngine.run (crawl + selected checks)
        → normalize findings → de-dup by fingerprint
        → risk_engine.compute_risk (explainable)
        → attach POTENTIAL MITRE techniques
        → notifications for HIGH/CRITICAL, audit log
      → correlation_engine.build_correlations
```

In local/dev/test (no `REDIS_URL`) Celery runs **eagerly** (in-process), so a scan completes
inline. In production a separate worker consumes from Redis.

## Data model (19 tables)

`users`, `organizations`, `organization_memberships` · `projects`, `assets`,
`asset_relationships` · `scans`, `findings` · `security_events`, `detection_rules`, `alerts`,
`mitre_techniques` · `correlations`, `finding_techniques` · `audit_logs`, `reports`,
`notifications`, `notification_preferences`, `ai_sessions`.

Tenancy is hierarchical: **Organization → Project → Asset → Scan → Finding / Alert → Report.**
Every tenant-scoped query is resolved through the requester's organization membership.

## Engines

- **Risk** (`services/risk_engine.py`) — `risk = 100 · Σ(weightᵢ · factorᵢ)` over severity, asset
  criticality, exposure, confidence and age. Weights sum to 1.0; each contribution is stored so
  the score is fully reconstructable.
- **Detection** (`services/detection_engine.py`) — evaluates declarative rules (event type,
  `conditions.match`, `group_by`, `threshold`, `window_seconds`) over `security_events` and
  raises/updates de-duplicated alerts.
- **Correlation** (`services/correlation_engine.py`) — recomputes explained edges; e.g. a
  finding's POTENTIAL technique matching an alert's OBSERVED technique links them and elevates the
  alert to `CORRELATED`. Manual edges are preserved.
- **Graph** (`services/graph.py`) — builds nodes/edges from the relational model plus correlation
  edges. No graph database.
- **AI analyst** (`services/ai_analyst.py`) — read-only; deterministic answers from stored data,
  with an optional LLM narrative layer behind prompt-injection defenses.

## Configuration

All configuration is environment-driven (`app/core/config.py`). SQLite is the default database so
the platform runs with no external services; set `DATABASE_URL` to Postgres and `REDIS_URL` to a
broker for production (docker-compose does both).
