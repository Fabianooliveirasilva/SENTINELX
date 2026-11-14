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
  "version": "0.12.0",
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

### Findings (Phase 5)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `GET /projects/{id}/findings` | `findings:read` | Most severe first. Filters: `status`, `active`, `severity`, `asset_id`, `source`, `search` |
| `GET /projects/{id}/findings/summary` | `findings:read` | Counts by status; open + acknowledged by severity |
| `GET /projects/{id}/findings/{finding_id}` | `findings:read` | Description, remediation, references, latest 20 occurrences (observation snapshots), status history |
| `POST /projects/{id}/findings/{finding_id}/status` | `findings:write` | `{status, reason}`; reason required for `false_positive`, `accepted_risk`, `resolved`; 409 if unchanged |

`GET /scanners` now also lists `nuclei` (`baseline`, `exposures`) and `zap`
(`baseline` = active, `full` = **intrusive**); each profile reports its technique.

### Threat intelligence (Phase 6)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `GET /intelligence/cves` | `intelligence:read` | Local CVE store, highest CVSS first. Filters: `search` (CVE ID or description), `severity`, `kev`, `vendor`, `product` |
| `GET /intelligence/cves/{cve_id}` | `intelligence:read` | CVSS v3.1/v4.0, CWE, KEV dates, references, affected CPE ranges; 404 if not stored |
| `GET /intelligence/status` | `intelligence:read` | Stored CVE/KEV counts, feed and per-product sync state, whether an NVD key is configured |
| `POST /intelligence/products/sync` | `settings:manage` | `{vendor, product}` → **202**; queues an NVD refresh (audited) |
| `GET /projects/{id}/software` | `assets:read` | Software inventory (product, version, location, CPE mapping, correlatable) |

### Risk (Phase 7)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `GET /risk/model` | `findings:read` | Model version, formula, bands, current/default weights and bounds |
| `PUT /risk/weights` | `settings:manage` | `{weights: {...}}` (partial allowed); validated, audited, rescores every finding; returns the count changed |
| `POST /risk/weights/reset` | `settings:manage` | Restore defaults and rescore |
| `GET /projects/{id}/risk` | `findings:read` | Posture (score, band, counts), top 10 risks, 30-day trend |

Findings now include `risk_score`, `risk_band` and `cve_id`; the list accepts
`risk_band` and `sort=risk|severity|last_seen` (default `risk`); the detail adds
`risk_factors`, `risk_explanation`, `risk_model_version`, `risk_calculated_at` and
`risk_history`. See [RISK_MODEL.md](RISK_MODEL.md).

### Monitoring & events (Phase 8)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `GET /events/types` | `events:read` | Catalog of event types with descriptions |
| `GET /projects/{id}/events` | `events:read` | Timeline, newest first; filters `event_type` (repeatable), `min_severity`, `asset_id`, `since`, `until`; paginated |
| `GET /projects/{id}/events/summary` | `events:read` | Counts by severity over `days` (default 7) |
| `GET /projects/{id}/alert-rules` | `events:read` | Rules with their channels (names only) |
| `POST /projects/{id}/alert-rules` | `alerts:manage` | `{name, event_types[], min_severity, asset_id?, quiet_period_minutes, channel_ids[]}` → 201 |
| `PATCH`/`DELETE /projects/{id}/alert-rules/{rule_id}` | `alerts:manage` | Partial update / 204 |
| `GET /projects/{id}/notification-channels` | `alerts:manage` | Destinations (recipients or URL); never the secret |
| `POST /projects/{id}/notification-channels` | `alerts:manage` | `{name, kind: email\|webhook, recipients?, url?}` → 201; webhooks return `signing_secret` **once** |
| `PATCH`/`DELETE /projects/{id}/notification-channels/{channel_id}` | `alerts:manage` | Rename, enable/disable, change destination / 204 |
| `POST /projects/{id}/notification-channels/{channel_id}/rotate-secret` | `alerts:manage` | New signing secret, returned once |
| `POST /projects/{id}/notification-channels/{channel_id}/test` | `alerts:manage` | 202; queues a `notification.test` delivery |
| `GET /projects/{id}/notifications` | `alerts:manage` | Delivery log; filter `status` (pending/sent/failed/suppressed) |
| `GET /projects/{id}/scan-schedules` | `scans:read` | Schedules with last run status and skip reason |
| `POST /projects/{id}/scan-schedules` | `scans:execute` | `{asset_id, scanner, profile?, interval_hours (1–2160), first_run_at?}` → 201 |
| `PATCH`/`DELETE /projects/{id}/scan-schedules/{schedule_id}` | `scans:execute` | Enable/disable, interval, profile, next run / 204; the editor becomes the owner |

**Webhook deliveries** are `POST` requests with a JSON body
`{"delivery_id": "...", "event": {id, type, severity, title, occurred_at, project_id, asset_id, finding_id, scan_job_id, actor, details}}`
and the headers `X-SentinelX-Event`, `X-SentinelX-Delivery` and
`X-SentinelX-Signature: t=<unix>,v1=<hex>`, where
`v1 = HMAC-SHA256(secret, "<t>." + raw_body)`. Receivers should verify the
signature with a constant-time comparison and reject timestamps older than a few
minutes. Any 2xx is success; 408, 429 and 5xx are retried with exponential
backoff; other statuses and refused destinations fail permanently.

Event titles and details can contain scanner-derived text and must be rendered as text.

### Reports (Phase 10)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `POST /projects/{id}/reports` | `reports:generate` | `{scope: project\|scan, scan_job_id?, format: pdf\|json, title?, include_resolved, include_ai, include_evidence}` → 202; poll until `completed` |
| `GET /projects/{id}/reports` | `reports:read` | History (status, size, SHA-256, summary); never the content |
| `GET /projects/{id}/reports/{report_id}` | `reports:read` | Status |
| `GET /projects/{id}/reports/{report_id}/download` | `reports:read` | The file (`application/pdf` or `application/json`), `Content-Disposition: attachment`, `X-Content-SHA256`, `Cache-Control: no-store`; 409 until completed; audited |
| `DELETE /projects/{id}/reports/{report_id}` | `reports:generate` | 204; audited |

The JSON format is the report document itself (`schema_version:
"sentinelx-report/1.0"`): `report`, `project`, `executive_summary`, `scope`
(`assets`, `authorizations`), `methodology`, `scans`, `tool_versions`,
`severity_distribution`, `findings[]` (with `evidence[]` excerpts), `remediation_plan`,
`ai_commentary[]` (reviewed analyses only, each with `label`, `provider`, `model`,
`prompt_version`, `reviewed_by`) and `limitations`.

### AI analyst (Phase 9)

| Method & path | Permission | Notes |
|---------------|------------|-------|
| `GET /projects/{id}/ai/usage` | `findings:read` | Provider enabled, model, tokens and estimated cost today, daily budget |
| `POST /projects/{id}/ai/analyses` | `ai:use` | `{kind, subject_id?, compare_with?, refresh?}` → 202 with the analysis; `kind` is `finding_analysis`, `scan_summary`, `scan_comparison` (needs `compare_with`, same asset, both completed), `executive_summary` or `technical_summary`. An identical recent request returns the existing analysis unless `refresh` is true |
| `GET /projects/{id}/ai/analyses` | `findings:read` | Filters `subject_id`, `kind`; newest first |
| `GET /projects/{id}/ai/analyses/{analysis_id}` | `findings:read` | Poll until `status` is `completed` or `failed` |
| `POST /projects/{id}/ai/analyses/{analysis_id}/review` | `ai:use` | Records the reviewer; 409 if not completed or already reviewed |

An analysis carries `provider` (`anthropic` or `deterministic`), `model`,
`prompt_version`, `fallback_reason`, `warnings` (validation corrections), token
counts and `cost_usd`. `output` follows one schema: `title`, `summary`,
`sections[].claims[]` (`text`, `basis`, `references`), `recommended_actions[]`,
`investigation_steps[]`, `limitations[]`, `confidence`. References name context
items (`F` finding, `E` evidence, `I` intelligence, `R` risk, `S` scan, `D` delta,
`P` posture, `A` asset). Output text may echo scanner-derived data and must be
rendered as text.

Observation data and evidence originate from scanned systems and are untrusted;
they are returned as JSON/text and must be rendered as text.

Authentication: `Authorization: Bearer <access_token>`. `401` responses include
`WWW-Authenticate: Bearer`; `429` responses include `Retry-After`. Details in
[AUTHENTICATION.md](AUTHENTICATION.md).

## Multi-factor authentication and metrics (Phase 12)

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /auth/login` | — | Returns `{mfa_required: true, challenge_token, expires_in}` when the account has MFA, otherwise the usual tokens |
| `POST /auth/mfa/verify` | challenge token | `{challenge_token, code}` (TOTP or recovery code) → tokens + cookies; 401 `Invalid or expired verification code.` otherwise |
| `GET /auth/mfa` | bearer | `{enabled, pending_enrollment, recovery_codes_remaining}` |
| `POST /auth/mfa/enroll` | bearer | `{password}` → `{secret, otpauth_uri}`; 409 when already enabled |
| `POST /auth/mfa/confirm` | bearer | `{code}` → `{recovery_codes}` (shown once) |
| `POST /auth/mfa/disable` | bearer | `{password, code}` → 204 |
| `POST /users/{id}/mfa/reset` | `users:manage` | 204; removes the second factor and signs the user out everywhere |
| `GET /metrics` (not under `/api`) | none, or `Bearer SENTINELX_METRICS_TOKEN` | Prometheus text format; Nginx answers 404, scrape `http://api:8000/metrics` on the internal network |

Metrics: `sentinelx_http_requests_total{method,route,status}`,
`sentinelx_http_request_duration_seconds{method,route}` (route = template, never a
concrete path or identifier), `sentinelx_scan_jobs{status}`,
`sentinelx_queue_length{queue}`, `sentinelx_build_info{version}`.

## Dashboard (Phase 11)

| Endpoint | Permission | Notes |
|---|---|---|
| `GET /dashboard?project_id=` | `projects:read` | Read-only aggregate over the projects the caller can access (all, or one). `project_id` of an inaccessible project → 404. Returns totals, posture (score, band, worst project), 30-day posture trend, risk distribution, assets by exposure, 14-day scan activity, 8-week remediation flow, status breakdown, closed ratio, recent findings and a project ranking; `empty: true` when the caller has no projects. |

## Cross-project views (Phase 11)

| Endpoint | Permission | Notes |
|---|---|---|
| `GET /vulnerabilities` | `findings:read` | Findings across the projects the caller can access, highest risk first. Filters: `project_id` (inaccessible → 404), `severity`, `status`, `active` (default `true`: open + acknowledged; ignored when `status` is given), `search` (title; `%`/`_` are literal), `page`, `page_size`. Includes `by_severity` counts for the filtered set. |
| `GET /reconnaissance` | `assets:read` | Active assets by type and exposure, assets registered in the last 7 days, scans of the last 30 days by scanner and status, the 10 most recent assets and scans. `empty: true` when the caller has no projects. |

## Planned resources


`/settings` —
introduced phase by phase (see [ROADMAP.md](ROADMAP.md)).
