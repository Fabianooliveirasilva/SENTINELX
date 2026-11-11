# SentinelX Roadmap

Each phase ends with: implementation, passing tests, security review, updated
documentation and an explicit approval before the next phase starts.

## Phase overview

| # | Phase | Key deliverables | Status |
|---|-------|------------------|--------|
| 1 | Foundation & architecture | Monorepo, API/worker/web skeletons, PostgreSQL, Redis, Docker Compose, health checks, logging, test foundations, CI | **Delivered** |
| 2 | Identity, access & tenancy | Users, Argon2id, access + rotating refresh tokens, session revocation, password reset, RBAC (Admin / Security Analyst / Viewer), projects, audit log foundation, rate limiting, CSRF, login UI | Planned |
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
| Authentication and RBAC working | 2 |
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

## Phase 2 proposal — Identity, access & tenancy

* Models + migrations: `users`, `roles`, `permissions`, `role_permissions`,
  `refresh_tokens`, `projects`, `project_members`, `audit_logs`.
* Argon2id (`argon2-cffi`) with OWASP-recommended parameters; constant-time
  verification; transparent rehash on parameter change.
* Short-lived JWT access tokens (≈10 min) in memory; opaque refresh tokens stored
  hashed, rotated on every use with reuse detection (family revocation), delivered
  as `HttpOnly; Secure; SameSite=Strict` cookies; CSRF double-submit for
  cookie-authenticated endpoints.
* Permission-based authorization dependencies (`require_permission("assets:write")`)
  scoped by project membership; deny-by-default; privilege-escalation tests.
* Redis-backed rate limiting for auth endpoints; account lockout with back-off.
* Password reset with single-use, hashed, expiring tokens (email delivery behind
  the notification abstraction; console sink in development).
* Frontend: login, session handling, route guards, user & role management.
