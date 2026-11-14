# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
