# SentinelX API

Base path: `/api/v1`. Interactive documentation is served at `/api/docs`
(Swagger UI) and `/api/openapi.json` outside production.

## Conventions

| Topic | Convention |
|-------|------------|
| Format | JSON (`application/json`), UTF-8, `snake_case` fields |
| Identifiers | UUIDs |
| Timestamps | ISO 8601 in UTC |
| Pagination _(Phase 2+)_ | `?page=1&page_size=50` (max 200); response `{items, total, page, page_size}` |
| Filtering / sorting _(Phase 2+)_ | Explicit query parameters per resource; `?sort=-created_at` with an allowlist of fields |
| Long-running work | `202 Accepted` with `{job_id, status}`; state via `GET /scans/{job_id}` |
| Correlation | Send `X-Request-ID` (8–64 chars, `[A-Za-z0-9._-]`) or receive a generated one in every response |
| Auth _(Phase 2)_ | `Authorization: Bearer <access token>`; refresh via HttpOnly cookie |

## Error envelope

Every non-2xx response (except readiness, which returns a report) uses:

```json
{
  "error": {
    "code": "validation_error",
    "message": "The request payload is invalid.",
    "request_id": "2f1c0f0e-8a7b-4c39-9a51-0c1f3c1f0f7e",
    "details": [{ "location": ["body", "count"], "message": "Input should be a valid integer", "type": "int_parsing" }]
  }
}
```

`code` is stable and machine-readable; `message` is safe to display. Submitted
values and exception messages are never echoed back.

## Endpoints (Phase 1)

### `GET /api/v1/health/live`
Liveness probe; does not touch dependencies. `200 {"status": "ok"}`.

### `GET /api/v1/health/ready`
Readiness probe; checks PostgreSQL and Redis concurrently with a timeout.

`200` when all components are reachable, otherwise `503` with the same shape:

```json
{
  "status": "unavailable",
  "version": "0.1.0",
  "components": {
    "database": { "status": "ok", "latency_ms": 1.8, "error": null },
    "redis": { "status": "unavailable", "latency_ms": null, "error": "timeout" }
  }
}
```

`error` is limited to `timeout` or `unreachable`; details are only in server logs.

## Endpoints (Phase 2)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `POST /auth/login` | public | Rate limited; sets refresh + CSRF cookies |
| `POST /auth/refresh` | refresh cookie + `X-CSRF-Token` | Rotates the refresh token |
| `POST /auth/logout` | refresh cookie + `X-CSRF-Token` | 204; idempotent |
| `GET /auth/me` | authenticated | User, role and permissions |
| `POST /auth/change-password` | authenticated | Signs out every session |
| `GET /auth/sessions` · `DELETE /auth/sessions/{id}` | authenticated | Own sessions only |
| `POST /auth/password-reset/request` · `/confirm` | public | 202 regardless of account existence |
| `POST /auth/register` | public | 403 unless self-registration is enabled |
| `GET /users` · `GET /users/{id}` | `users:read` | Filters: `search`, `role`, `is_active`; `sort` |
| `POST /users` · `PATCH /users/{id}` | `users:manage` | Role/status changes audited |
| `POST /users/{id}/revoke-sessions` | `users:manage` | Forced sign-out |
| `GET /roles` | `roles:read` | Roles with permissions |
| `GET /projects` · `GET /projects/{id}` | `projects:read` | Membership-scoped; 404 outside scope |
| `POST/PATCH/DELETE /projects…` | `projects:manage` | |
| `GET /projects/{id}/members` | `projects:read` | |
| `POST /projects/{id}/members` · `DELETE …/{user_id}` | `projects:manage` | |
| `GET /audit-logs` · `GET /audit-logs/actions` | `audit:read` | Filters: `action`, `actor_id`, `project_id`, `outcome`, `since`, `until` |

### Assets & scope (Phase 3)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `GET /projects/{id}/assets` | `assets:read` | Filters: `type`, `status`, `criticality`, `tag`, `search` |
| `POST /projects/{id}/assets` | `assets:write` | Normalized; internal/special-use targets rejected; 409 on duplicates |
| `GET /projects/{id}/assets/{asset_id}` | `assets:read` | Includes eligibility and authorizations |
| `PATCH /projects/{id}/assets/{asset_id}` | `assets:write` | Description, tags, criticality, exposure, status (type/value immutable) |
| `GET /projects/{id}/assets/{asset_id}/history` | `assets:read` | From the audit log |
| `POST /projects/{id}/assets/{asset_id}/authorizations` | `assets:write` | Intrusive requires admin |
| `POST /projects/{id}/assets/{asset_id}/authorizations/{auth_id}/revoke` | `assets:write` | Reason required |
| `POST /projects/{id}/scope/check` | `assets:read` | `{target, technique}` → decision with reasons and per-address verdicts; rate limited |

### Scans (Phase 4)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `GET /scanners` | `scans:read` | Catalog: technique, supported asset types, profiles |
| `GET /projects/{id}/scans` | `scans:read` | Filters: `status`, `asset_id`, `scanner` |
| `POST /projects/{id}/scans` | `scans:execute` | `{asset_id, scanner, profile?}` → **202** with the job; 422 if not eligible, 409 while halted, 429 on quota, 503 if the queue is down |
| `GET /projects/{id}/scans/{scan_id}` | `scans:read` | Job + execution-time scope decision, pinned addresses, observations, evidence, tool versions |
| `POST /projects/{id}/scans/{scan_id}/cancel` | `scans:execute` | Pending, queued or running jobs only (409 otherwise) |
| `GET /scans/controls` | `scans:read` | Emergency-stop state |
| `POST /scans/emergency-stop` | `settings:manage` | `{reason}`; cancels every active job platform-wide |
| `POST /scans/resume` | `settings:manage` | Lifts the emergency stop |

Observation data and evidence originate from scanned systems and are untrusted;
they are returned as JSON/text and must be rendered as text.

Authentication: `Authorization: Bearer <access_token>`. `401` responses include
`WWW-Authenticate: Bearer`; `429` responses include `Retry-After`. Details in
[AUTHENTICATION.md](AUTHENTICATION.md).

## Planned resources

`/findings`,
`/intelligence`, `/events`, `/reports`, `/ai`, `/settings` —
introduced phase by phase (see [ROADMAP.md](ROADMAP.md)).
