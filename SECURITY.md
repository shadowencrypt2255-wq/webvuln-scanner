# Security Policy

## Authorized use only

SentinelX is a security-assessment platform that sends real requests, attack payloads, and
login attempts to targets. **Only use it against assets you own or are explicitly authorized to
test** (e.g. your own systems, a lab, a CTF, or an engagement with written authorization).

The platform enforces this in two independent layers:

1. **Authorization gate (data layer).** An asset must be explicitly marked `AUTHORIZED` before
   any scan will run against it. Scans of non-authorized assets are refused and audit-logged.
2. **SSRF guard (network layer).** Targets that resolve to private, loopback, link-local,
   multicast or reserved addresses are refused unless `ALLOW_PRIVATE_SCAN_TARGETS=true` is set
   for an authorized local lab.

Additional safety controls: per-scan rate limiting, concurrency limits, a hard scan deadline,
cooperative scan cancellation, and full audit logging.

## What SentinelX does not do

It focuses on **discovery → assessment → detection → correlation → risk → remediation**. It does
**not** provide functionality whose primary purpose is unauthorized exploitation, credential
theft, malware deployment, persistence, evasion, or destructive attacks.

## Secrets

- No secrets are committed. Configuration comes from environment variables / `.env` (git-ignored).
- `SECRET_KEY` is required in production; the app refuses to start in `production` without it.
- Passwords are hashed with Argon2id. Audit logs redact secret-like fields.

## AI safety

The AI analyst is read-only and tool-bounded: it never executes scans, shell commands, or writes
to authoritative security records, never retrieves secrets, and never bypasses RBAC. Untrusted
data (findings text, questions) passed to an optional LLM is delimited with prompt-injection
defenses, and answers separate **facts** from **AI-generated analysis**.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers via a GitHub security
advisory (or a direct maintainer contact) rather than a public issue. Include reproduction steps
and impact. We aim to acknowledge within a few business days.
