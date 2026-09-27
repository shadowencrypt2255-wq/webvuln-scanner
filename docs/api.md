# API

The REST API is versioned under `/api/v1`. Interactive OpenAPI docs are served at `/docs`
(schema at `/api/v1/openapi.json`). Authenticate with a bearer access token from
`POST /api/v1/auth/login`.

## Conventions
- **Auth:** `Authorization: Bearer <access_token>`.
- **Errors:** `{ "detail": "...", "request_id": "..." }` with appropriate HTTP status.
- **Pagination:** list endpoints return `{ items, total, page, page_size }`; use `?page=&page_size=`.
- **Filtering:** e.g. findings accept `severity`, `status`, `asset_id`, `cve`.

## Endpoint groups

| Group | Examples |
|-------|----------|
| Auth | `POST /auth/register`, `/auth/login`, `/auth/refresh`, `GET /auth/me`, `POST /auth/change-password` |
| Organizations | `GET/POST /organizations`, `.../members` (add/update/remove) |
| Projects | `GET/POST /organizations/{id}/projects`, `GET/PATCH/DELETE /projects/{id}` |
| Assets | `GET/POST /projects/{id}/assets`, `GET/PATCH/DELETE /assets/{id}`, `POST /assets/{id}/authorize` |
| Scans | `GET/POST /projects/{id}/scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /scans/{id}/findings` |
| Findings | `GET /projects/{id}/findings`, `GET/PATCH /findings/{id}`, `GET /findings/{id}/techniques` |
| Detection | `POST/GET /projects/{id}/events`, `GET/POST /organizations/{id}/detection-rules`, `PATCH /detection-rules/{id}`, `GET /projects/{id}/alerts`, `GET/PATCH /alerts/{id}` |
| MITRE | `GET /mitre/techniques`, `GET /mitre/techniques/{tid}` |
| Insights | `GET /projects/{id}/correlations`, `POST .../correlations/rebuild`, `GET /projects/{id}/graph`, `GET /projects/{id}/dashboard` |
| Reports | `GET/POST /projects/{id}/reports`, `GET /reports/{id}`, `GET /reports/{id}/download` |
| Governance | `GET /organizations/{id}/audit`, `GET /organizations/{id}/notifications`, `.../me/notification-preferences` |
| AI | `POST /ai/query` |
| Admin | `GET/POST /admin/users`, `POST /admin/users/{id}/activate|deactivate` (superuser) |
| Ops | `GET /health`, `GET /ready` |

## Example

```bash
TOKEN=$(curl -s localhost:8000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"demo@sentinelx.io","password":"SentinelX-demo-1234"}' | jq -r .access_token)

curl -s localhost:8000/api/v1/projects/1/dashboard -H "Authorization: Bearer $TOKEN" | jq
```
