# Security model & threat model

## Authentication & sessions
- Argon2id password hashing (`app/core/security.py`), opportunistic rehash on login.
- JWT access + refresh tokens; access tokens are short-lived, refresh tokens exchange for new
  access tokens. Tokens are typed (`access`/`refresh`) and validated.
- Failed logins are counted; the account locks for `LOCKOUT_MINUTES` after `MAX_FAILED_LOGINS`.
- Login is rate-limited per client IP + email.

## Authorization (RBAC + tenancy)
- Roles `ADMIN` / `SECURITY_ANALYST` / `VIEWER` map to explicit permission sets
  (`app/core/rbac.py`), enforced on every endpoint via `app/api/deps.py`.
- Tenant isolation: a resource is loaded, its owning organization resolved, and the caller's
  membership checked. Non-members receive **404** (existence is not leaked); members lacking a
  permission receive **403**. Superusers hold all permissions.

## Scan safety
- **Authorization gate:** scanning requires the asset to be `AUTHORIZED`.
- **SSRF guard** (`app/core/netsafe.py`): targets resolving to private/loopback/link-local/
  reserved IPs are refused unless `ALLOW_PRIVATE_SCAN_TARGETS=true` (local lab).
- Rate limiting, concurrency cap, per-request timeout, hard scan deadline, cooperative cancel.

## Input / output handling
- Pydantic validates all request bodies and query parameters.
- SQLAlchemy parameterized queries (no string-built SQL) — the only intentionally-vulnerable SQL
  is in the **testbed**, which is never deployed.
- Errors are returned as structured JSON with a request id; stack traces are never sent to
  clients (`app/main.py` exception handlers). `APP` runs with debug off.

## Transport & headers
- Security headers on every response (CSP, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`; HSTS in production).
- CORS restricted to configured origins.

## Secrets & audit
- No secrets in source; `.env` is git-ignored and `SECRET_KEY` is mandatory in production.
- Audit logs record security-sensitive actions with actor, action, resource, result, IP and
  request id, and **redact** secret-like fields.

## AI safety
- Read-only, tool-bounded; never executes actions or reads secrets, never bypasses RBAC.
- Facts (authoritative data) are separated from AI-generated analysis; untrusted text is delimited
  with an anti-prompt-injection instruction before any LLM call, which is optional and off by
  default.

## Threats considered
SQL injection, XSS, CSRF (stateless bearer-token API, no ambient cookies), SSRF, command injection
(no shell execution from user input), path traversal, IDOR / broken access control (tenant checks
+ 404s), authentication bypass, JWT issues, rate-limit bypass, secret leakage, CORS, security
headers, and prompt injection. See [AUDIT.md](AUDIT.md) for the review results and residual risks.
