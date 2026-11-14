# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.9.0] — 2026-11-13 — Phase 9: AI security analyst

### Added
- AI analyses (`ai_analyses`): finding analysis, scan summary, scan comparison,
  executive and technical summaries; asynchronous jobs with provenance (provider,
  model, prompt version, context summary, tokens, cost, duration).
- Provider abstraction with an Anthropic implementation (official SDK,
  `claude-opus-5-5`, structured outputs, configurable effort, server-side refusal
  fallback, cached system prompt); deterministic analyses with the same schema
  whenever the provider is disabled, unconfigured, over budget or failing.
- Versioned prompts; every claim labelled as confirmed evidence, scanner
  hypothesis, external intelligence or AI recommendation, with references.
- `ai` worker on its own `ai` queue and `ai-egress` network (the only container
  with the API key); per-project daily token budget, result reuse, usage endpoint.
- Human review of analyses (recorded and audited).
- API under `/projects/{id}/ai/…`; UI: AI panels on finding and scan pages, project
  AI analyst page. Migration `0009`.

### Security
- Pseudonymization of asset values, hostnames (including any host in a URL),
  IP addresses and e-mail addresses before data leaves the platform; redaction of
  credential-looking values; scanner text delimited and labelled untrusted.
- Server-side validation of model output: unknown references removed, unsupported
  claim bases downgraded, claims naming CVEs outside the assessment data dropped.
- Log fields for AI usage renamed so the log redactor does not mask them.

## [0.8.0] — 2026-11-12 — Phase 8: Monitoring & events

### Added
- `security_events` timeline written atomically with the change that caused it:
  finding created/reopened/resolved/status changed, risk-band changes, CISA KEV
  listings, certificate expiry, scan completed/failed/cancelled/scope-denied,
  emergency stop/resume, asset and authorization changes, skipped schedules.
- Alert rules per project (event types, minimum severity, optional asset,
  channels, quiet period with recorded suppressions).
- Notification channels: e-mail and HMAC-SHA256 signed webhooks; outbox with
  retries, exponential backoff and a delivery log; test notifications.
- `smtp` e-mail backend (STARTTLS or implicit TLS, verified certificates).
- Scheduled scans that run as their owner through the interactive request path.
- `notifier` worker on its own `notifications` queue and `notify-egress` network;
  beat entries for delivery (30 s) and schedules (60 s).
- Permission `alerts:manage` (admin, security analyst); migration `0008`.
- API: `/events/types`, `/projects/{id}/events`, `/events/summary`,
  `/notification-channels`, `/alert-rules`, `/notifications`, `/scan-schedules`.
- UI: project Events, Alerts and Schedules tabs.

### Security
- Webhook destinations are resolved per delivery, every address must pass the
  network policy, and the request is pinned to the checked IP (no redirects, no
  proxies, bodies never read); https is required in production, re-checked at
  delivery time. Signing secrets are generated server-side, shown once and
  encrypted at rest (Fernet, HKDF-derived key); audit records keep only the host.

### Fixed
- Scan jobs are queued before their Celery chain is published; a fast worker
  could previously skip a job still marked `pending` (present since Phase 4).

## [0.7.0] — 2026-11-12 — Phase 7: Risk engine

### Added
- `sentinelx_security.risk`: deterministic, versioned (1.0.0) risk model —
  CVSS/severity base x confidence x asset criticality x exposure, plus CISA KEV,
  EPSS and exposure-window points; factor breakdown and plain-language explanation;
  bounded, validated weights; project posture that never drops below the worst issue.
- FIRST EPSS client and daily sync for CVEs referenced by active findings.
- Risk columns on findings, `finding_risk_changes` history, daily
  `project_risk_snapshots`, EPSS columns on CVEs (migration 0007, with `cve_id`
  backfill).
- Rescoring on scan, correlation, asset criticality/exposure edits, KEV/EPSS
  updates, weight changes and a daily task.
- API: risk model and admin weights (audited, rescoring), project risk posture;
  findings sortable/filterable by risk. UI: risk column and sort, factor
  breakdown and history, project Risk tab with trend, Risk Model page.
- `docs/RISK_MODEL.md`.

## [0.6.0] — 2026-11-12 — Phase 6: Threat intelligence

### Added
- `sentinelx_security.intel`: NVD CVE API 2.0 client (pagination, API key, rate
  spacing, bounded backoff, window splitting, size caps, defensive parsing), CISA
  KEV parser, CPE 2.3 parsing and version-range matching, software inventory
  extraction and CVE correlation.
- Tables `cves`, `cve_matches`, `intel_product_syncs`, `intel_sources`,
  `software_components` (migration 0006).
- Product-driven sync: products observed by scans are fetched from NVD by an
  `intel` worker (own queue and egress network), refreshed after a TTL; KEV daily.
- CVE findings (`cve.<ID>`, source `intel`, always `tentative`) through the
  standard finding lifecycle; upgrades auto-resolve; late refreshes re-correlate.
- API: CVE search/detail, intelligence status, admin product sync, project
  software inventory. UI: Threat Intel page, CVE detail, Software tab, CVE links
  from findings.

### Changed
- Finding ingestion generalized (`IngestScope`) so non-scan sources share the
  same deduplication, regression and auto-resolution rules.

## [0.5.0] — 2026-11-11 — Phase 5: Vulnerability assessment

### Added
- Findings (`findings`, `finding_occurrences`, `finding_status_changes`): stable
  fingerprints, severity, confidence, CWE, remediation, references; versioned,
  deterministic rules turn TLS, HTTP-header, DNS/e-mail and exposed-service
  observations into findings; ZAP/Nuclei verdicts mapped without upgrading.
- Lifecycle: new/updated on every completed scan, regressions reopen resolved
  findings, absent issues auto-resolve per scanner and profile, analyst
  `false_positive`/`accepted_risk` decisions (reason required) are respected.
- Egress guard: per-scan forward proxy admitting only the authorized host:port,
  connecting to pinned IPs without DNS, with budgets and denied-destination evidence.
- Nuclei adapter: pinned v3.11.1 binary and templates v10.5.1 (SHA-256 verified
  at build), allowlisted template directories, `http` protocol only, excluded
  intrusive/exploit tags, interactsh and update checks disabled.
- OWASP ZAP 2.17 daemon on an internal-only network, driven through its API by a
  dedicated `scanner-zap` worker (`scans.zap` queue, serialized); `baseline`
  profile (spider + passive) and `full` profile (active, **intrusive**).
- Per-profile techniques in the scanner contract; per-scanner timeouts.
- API: findings list/summary/detail/triage. UI: Findings tab, finding detail
  with evidence and history, triage dialog, findings delta on scan details.

### Changed
- Scanner subprocesses (Nmap, Nuclei) get a minimal environment and never inherit
  the worker's broker credentials.

## [0.4.0] — 2026-11-11 — Phase 4: Scan orchestration & reconnaissance

### Added
- Scan jobs persisted in PostgreSQL (`scan_jobs`, `scan_results`, `scan_evidence`)
  with states `pending → queued → running → completed | failed | cancelled`;
  `POST /projects/{id}/scans` returns `202` with the job.
- Three-step Celery chain: orchestrator `start` (snapshot scope, mark running) →
  sandboxed `execute` (fresh-DNS scope re-check, pinned IPs) → orchestrator `record`.
- Scanner sandbox: separate Celery app, `scans` queue and `sentinelx/scanner` image
  (non-root, no capabilities, read-only FS, CPU/memory/PID limits, no database
  credentials or secret key, process recycled after every scan, `scan-egress` network).
- Scanners: DNS posture (records, SPF, DMARC, CAA), passive certificate-transparency
  subdomain discovery with provenance, TLS analyzer (trust, expiry, key strength,
  legacy protocols), HTTP technology fingerprinting and security-header review,
  Nmap TCP-connect safe profiles with `defusedxml` parsing.
- Per-project concurrency and daily quotas, cancellation, platform-wide emergency
  stop and resume (`platform_settings`), periodic expiry of lost jobs; all audited.
- Frontend: Scans tab, scan configuration offering only eligible scanners and
  profiles, execution details (scope decision, observations, evidence rendered as
  text), emergency-stop controls.

### Changed
- `Scanner.target_for` is a class method; Nmap is limited to domain, subdomain and
  IP assets (an application/service authorization does not cover a host-wide port
  scan). A test asserts every scanner/asset combination yields an in-scope target.

## [0.3.0] — 2026-11-11 — Phase 3: Assets & scope enforcement

### Added
- `security-engine` workspace package (`sentinelx-security`) with the scope engine:
  strict target parsing (IDNA, canonical IPs, URLs, host:port; rejects numeric-host
  forms, zone IDs, credentials, wildcards), deny-by-default network policy
  (loopback, private, link-local, metadata, multicast, reserved; IPv4 embedded in
  IPv6 via mapped/compatible/NAT64/6to4/Teredo), DNS resolution with pinning,
  explained decisions per address, per-hop redirect validation, lab networks/domains.
- Assets (domain, subdomain, IP, web application, API endpoint, service) with
  normalization, tags, criticality, exposure, archive/restore and eligibility.
- Immutable authorization records with validity windows, technique flags,
  subdomain coverage and bounded IP ranges; revocation with reason; DB constraints.
- Asset history from the audit log; `POST /projects/{id}/scope/check`.
- Frontend: project tabs, asset inventory, asset detail (eligibility,
  authorizations, history) and scope check tool.

## [0.2.0] — 2026-11-11 — Phase 2: Identity, access & tenancy

### Added
- Users, roles, permissions (RBAC catalog seeded by migration and checked against code),
  refresh tokens, password-reset tokens, projects, project membership and an
  append-only audit log (database trigger rejects UPDATE/DELETE).
- Argon2id password hashing (OWASP parameters, transparent rehash), NIST-style
  length-based password policy, account lockout with uniform login timing.
- Short-lived JWT access tokens (HS256, issuer/audience/type/version checks) and
  rotating opaque refresh tokens in HttpOnly/SameSite=Strict cookies with reuse
  detection that revokes the whole session family.
- Signed double-submit CSRF tokens bound to the session family.
- Session listing and revocation, forced sign-out, password change and email-based
  password reset (single-use, hashed, expiring tokens in the URL fragment).
- Permission-based authorization dependency; project-scoped repositories returning
  404 for other tenants' resources; last-admin and self-demotion protection.
- Redis fixed-window rate limiting for authentication endpoints (fail-open).
- `sentinelx-admin create-admin` CLI for bootstrapping the first administrator.
- Frontend: login, password reset, route guards with safe `next` redirects, users &
  roles management, projects and members, audit log viewer, account settings,
  route-level code splitting.

### Fixed
- Web image: apply Alpine security updates (critical `brotli-libs` CVE flagged by Trivy).
- Alembic no longer disables application loggers when migrations run in-process.
- Coverage measurement with async SQLAlchemy (greenlet concurrency).

## [0.1.0] — 2026-11-10 — Phase 1: Foundation

### Added
- Monorepo: uv workspace (`apps/api`, `workers`) and pnpm-managed `apps/web`.
- FastAPI application factory with versioned `/api/v1` router and OpenAPI
  (disabled in production).
- Typed configuration with `pydantic-settings`, secret types and production guards.
- Liveness and readiness endpoints (PostgreSQL + Redis, concurrent, time-bounded).
- Async SQLAlchemy 2 engine, declarative base with naming conventions, Alembic
  (async) with a baseline revision.
- Structured JSON logging with correlation IDs, sensitive-key and URL-credential
  redaction.
- Consistent error envelope; unhandled errors return a generic 500 with request ID.
- Security headers, trusted-host allowlist, opt-in CORS allowlist.
- Celery worker with JSON-only serialization, time limits and a `system.ping` task.
- React 19 + TypeScript SPA: design tokens, app shell, typed Zod-validated API
  client, TanStack Query, System Status page on live data, 404 page.
- Docker images (non-root, multi-stage) and hardened Docker Compose stack with an
  internal backend network.
- CI: lint, strict typing, unit/API/integration tests, frontend build,
  Gitleaks, Bandit, Semgrep, pip-audit, pnpm audit; container build, Trivy, compose
  smoke and Playwright E2E; Dependabot.
- Documentation: architecture & ADRs, roadmap, database proposal, API, security,
  threat model, scanning policy, testing, deployment.
