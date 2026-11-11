# SentinelX Roadmap

Each phase ends with: implementation, passing tests, security review, updated
documentation and an explicit approval before the next phase starts.

## Phase overview

| # | Phase | Key deliverables | Status |
|---|-------|------------------|--------|
| 1 | Foundation & architecture | Monorepo, API/worker/web skeletons, PostgreSQL, Redis, Docker Compose, health checks, logging, test foundations, CI | **Delivered** |
| 2 | Identity, access & tenancy | Users, Argon2id, access + rotating refresh tokens, session revocation, password reset, RBAC (Admin / Security Analyst / Viewer), projects, audit log, rate limiting, CSRF, login UI | **Delivered** |
| 3 | Assets & scope enforcement | Asset inventory (domain, subdomain, IP, web app, API endpoint, service), authorization records, scope engine (DNS rebinding, private ranges, IPv6, redirects, SSRF), asset history, inventory UI | Planned |
| 4 | Scan orchestration & reconnaissance | Job model & states, scanner interface (`validate_scope/execute/normalize_results/handle_errors/record_evidence`), sandbox runner, DNS analyzer, passive subdomain discovery, TLS analyzer, Nmap safe profiles, technology fingerprinting | Planned |
| 5 | Vulnerability assessment | OWASP ZAP baseline (active only with explicit authorization), Nuclei curated/pinned templates, HTTP security checks, findings normalization, evidence, lifecycle states | Planned |
| 6 | Threat intelligence | NVD sync with rate limits and caching, CVE/CWE/CPE, version-range matching with confidence, provenance | Planned |
| 7 | Risk engine | Deterministic, versioned, explainable risk model; configurable weights | Planned |
| 8 | Monitoring & events | Event ingestion, alerts, timeline, filters, notification abstraction (email/webhook ready) | Planned |
| 9 | AI security analyst | Anthropic provider abstraction, structured outputs, prompt versioning, prompt-injection defenses, budgets, deterministic fallback | Planned |
| 10 | Reporting | PDF + JSON reports with scope, methodology, evidence, tool versions, AI content labeled | Planned |
| 11 | Dashboard & UX completion | Dashboard on real data, remaining pages, accessibility pass | Planned |
| 12 | Hardening & release | Metrics/observability, ZAP against SentinelX itself, container hardening review, release workflow, final docs | Planned |

## Mapping to the project success checklist

| Success criterion | Phase |
|-------------------|-------|
| Authentication and RBAC working | 2 ✅ |
| Registration and validation of authorized assets | 3 |
| DNS reconnaissance and TLS analysis | 4 |
| Functional Nmap integration | 4 |
| Functional OWASP ZAP integration | 5 |
| Controlled Nuclei integration | 5 |
| CVE lookup and correlation | 6 |
| Functional risk engine | 7 |
| Monitoring and event history | 8 |
| Anthropic API integration | 9 |
| PDF and JSON reports | 10 |
| Dashboard fed by real data | 11 |
| Working Docker Compose | 1 (foundation) → extended every phase |
| CI/CD with quality gates | 1 (foundation) → extended every phase |
| Unit, integration and E2E tests | 1 (foundation) → extended every phase |
| Complete documentation in English | 1 (foundation) → completed in 12 |

## Phase 1 acceptance criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Monorepo with API, workers and web app, one lockfile per ecosystem | `uv.lock`, `apps/web/pnpm-lock.yaml` |
| 2 | FastAPI app factory with versioned `/api/v1` router and OpenAPI (non-prod) | `tests/api/test_http_behaviour.py` |
| 3 | Typed, validated configuration; unsafe values rejected; production guards | `tests/unit/test_config.py` |
| 4 | Liveness and readiness endpoints; readiness checks DB + Redis with timeouts, 503 on failure, no internal details leaked | `tests/api/test_health.py`, `tests/integration/` |
| 5 | Async database connectivity and Alembic baseline migration (upgrade, downgrade, `alembic check`) | CI `backend-integration` job |
| 6 | Structured JSON logging with correlation IDs and secret redaction | `tests/unit/test_logging.py` |
| 7 | Consistent error envelope; unhandled errors return a generic 500 with request ID and security headers | `tests/api/test_http_behaviour.py` |
| 8 | Celery worker with safe defaults and a verifiable task | `workers/tests/`, compose smoke step |
| 9 | React + TypeScript SPA with design tokens, router, data layer and a page fed by real backend data | Vitest suite, Playwright E2E |
| 10 | Docker Compose: hardened services, internal backend network, health-gated startup, migrations before app start | `containers.yml` workflow, `make up && make smoke` |
| 11 | CI: lint, types, tests, build, secret scanning, SAST, dependency audit, image scan, compose smoke + E2E | `.github/workflows/` |
| 12 | Documentation: architecture, roadmap, database proposal, threat model, scanning policy, security, testing, deployment | `docs/` |

## Phase 2 — delivered

See [AUTHENTICATION.md](AUTHENTICATION.md) for the full design. Acceptance criteria:

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | Argon2id hashing, password policy, uniform timing for unknown accounts | `tests/unit/test_security_primitives.py`, `test_auth.py` |
| 2 | Short-lived access tokens; invalid/expired/`alg=none`/wrong-audience tokens rejected | `test_auth.py::test_invalid_access_tokens_are_rejected` |
| 3 | Refresh rotation with reuse detection revoking the session family | `test_refresh_token_reuse_revokes_the_whole_session` |
| 4 | CSRF on cookie-authenticated endpoints, bound to the session | `test_refresh_requires_matching_csrf_token`, `test_csrf_token_is_bound_to_its_session` |
| 5 | Logout, session listing/revocation, forced sign-out, immediate invalidation on password change / deactivation | `test_auth.py`, `test_rbac_users.py` |
| 6 | Password reset: single use, expiring, no account enumeration | `test_password_reset_*` |
| 7 | Lockout and rate limiting with `Retry-After` | `test_account_locks_after_repeated_failures`, `TestLoginRateLimit` |
| 8 | Server-side RBAC for every endpoint; DB seed equals code catalog; no mass assignment | `test_rbac_users.py` |
| 9 | Project isolation: non-members get 404; membership management | `test_projects_audit.py` |
| 10 | Append-only audit log with request correlation | `test_audit_log_is_append_only`, `test_audit_log_records_and_filters_actions` |
| 11 | UI: login, reset, guards, users & roles, projects, audit, account; RBAC-aware navigation | Vitest suite, Playwright `auth-rbac.spec.ts` |

## Phase 3 proposal — Assets & scope enforcement

* Models + migration: `assets`, `asset_authorizations`, `asset_history` (project-scoped).
* Asset types: domain, subdomain, IP address (v4/v6), CIDR range, web application,
  API endpoint, service; normalization (IDNA, lower-case, canonical IP forms) and
  uniqueness per project; tags, criticality, exposure, status, scan eligibility.
* Authorization records: authorized party, reference, validity window, permitted
  technique classes, recorded by; history of changes; expiry handling.
* **Scope engine** (deny-by-default, pure and exhaustively unit-tested):
  hostname/IP parsing, special-use and private range blocklists (incl. IPv4-mapped
  IPv6, NAT64, link-local, metadata endpoints), wildcard semantics, resolution with
  pinning (DNS-rebinding defense), redirect validation helper, and an explicit
  `ScopeDecision` with reasons.
* API: CRUD for assets and authorizations, `POST /scope/check` (dry run with
  explanation), eligibility computed server-side.
* Frontend: asset inventory, asset details with authorization timeline, scope check tool.
