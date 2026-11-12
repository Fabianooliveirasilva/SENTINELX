# Testing Strategy

SentinelX follows a testing pyramid: many fast, deterministic unit/API tests; a
focused set of integration tests against real PostgreSQL and Redis; and a small
number of end-to-end tests through the browser against the full stack.

**Rule:** no test, and no CI job, ever depends on a public third-party target.
Scanner integrations (Phase 4+) are tested with recorded, deterministic fixtures
and, for integration, against intentionally vulnerable labs on an isolated
network.

## Layers

| Layer | Tooling | Location | Needs infrastructure |
|-------|---------|----------|----------------------|
| Backend unit | Pytest | `apps/api/tests/unit`, `workers/tests` | No |
| Backend API | Pytest + HTTPX ASGI transport | `apps/api/tests/api` | No (health checks stubbed via DI) |
| Backend integration | Pytest (`-m integration`) | `apps/api/tests/integration` | PostgreSQL + Redis |
| Frontend unit/component | Vitest + React Testing Library (jsdom) | `apps/web/src/**/*.test.ts(x)` | No (fetch stubbed) |
| End-to-end | Playwright (Chromium) | `apps/web/tests/e2e` | Running stack |
| Security | Bandit, Semgrep, pip-audit, pnpm audit, Gitleaks, Trivy | CI | — |

## Running tests

```bash
make test                 # backend (with coverage gate ≥ 85%) + frontend
make test-integration     # requires SENTINELX_DATABASE_URL / SENTINELX_REDIS_URL
make up && make test-e2e  # E2E against docker compose (http://localhost:8080)
make security             # bandit, pip-audit, pnpm audit
```

Integration tests against the compose databases from the host require exposing
their ports; the simplest path is to run them in CI or inside the `api`
container. E2E can also run against a local Vite + API pair:

```bash
make dev-api & make dev-web &
E2E_BASE_URL=http://127.0.0.1:5173 make test-e2e
```

## Conventions

* `pytest` runs with `--strict-markers`, `--strict-config` and
  `filterwarnings = error`: deprecations fail the build early.
* Tests assert security properties explicitly (e.g. exception messages and
  submitted secrets are never echoed; headers are present on error responses).
* Each infrastructure dependency is reached through an injectable seam
  (`HealthCheck` protocol, `get_health_service` dependency), so failure and
  timeout paths are tested deterministically.
* Frontend tests use accessible queries (`getByRole`, labels) to keep
  components accessible by construction.

## Running integration tests without Docker

Integration tests need a real PostgreSQL. Any reachable instance works:

```bash
export SENTINELX_DATABASE_URL=postgresql+asyncpg://user:pass@127.0.0.1:5432/sentinelx
export SENTINELX_REDIS_URL=redis://127.0.0.1:6379/0
export SENTINELX_SECRET_KEY=local-test-secret-key-at-least-32-chars
make test-all
```

Fixtures apply migrations once per session and truncate tenant tables before each
test (RBAC seed rows are preserved). Redis-dependent behavior in API tests uses
`fakeredis`; the two tests that need a real Redis run in CI.

> Integration tests **truncate** the database they point at. Never run them
> against a database holding data you want to keep.

## Latest results (Phase 7, local run 2026-11-12)

| Suite | Result |
|-------|--------|
| Security engine (incl. risk model, EPSS client) | 264 passed, 1 skipped (real Nmap binary absent locally) |
| Backend full suite (unit + integration + engine + workers, PostgreSQL 16 local) | 486 passed; the 2 real-Redis tests run in CI; coverage 95% |
| Frontend (Vitest) | 58 passed |
| E2E (Playwright, Chromium, real API + PostgreSQL) | 8 passed |
| Live risk smoke (scan → NVD correlation → **live FIRST EPSS** → daily rescoring) | EPSS applied to 93 CVEs; 105 findings rescored; KEV + high-EPSS CVEs ranked first with factor breakdowns |
| Ruff / mypy strict / ESLint strict / tsc / Bandit | clean |

Risk tests assert that factor contributions always sum to the stored score, that
each risk input moves the score in the expected direction, and that the project
posture is never below the worst active finding.

## Phase 6 results (local run 2026-11-12)

| Suite | Result |
|-------|--------|
| Security engine (scope, scanners, findings, egress guard, NVD/KEV parsing, CPE matching, correlation) | 257 passed, 1 skipped (real Nmap binary absent locally) |
| Backend full suite (unit + integration + engine + workers, PostgreSQL 16 local) | 473 passed; the 2 real-Redis tests run in CI; coverage 95% |
| Frontend (Vitest) | 55 passed |
| E2E (Playwright, Chromium, real API + PostgreSQL) | 8 passed |
| Live intelligence smoke (scan → intel worker → **live NVD API** → correlation) | 956 CVEs fetched for 2 products; 93 tentative CVE findings; spot checks matched NVD ranges |
| Ruff / mypy strict / ESLint strict / tsc | clean |

NVD and KEV client tests use real API responses saved as fixtures
(`security-engine/tests/fixtures/nvd_page.json`, `kev_sample.json`) served through
`httpx.MockTransport`; the suite never calls the live feeds.

## Phase 5 results (local run 2026-11-11)

| Suite | Result |
|-------|--------|
| Security engine (scope, scanners, findings rules, egress guard, Nuclei/ZAP adapters) | 236 passed, 1 skipped (real Nmap binary absent locally) |
| Backend full suite (unit + integration + engine + workers, PostgreSQL 16 local) | 444 passed; 2 real-Redis tests run in CI (they pass against a `fakeredis` TCP server); coverage 95% |
| Frontend (Vitest) | 51 passed |
| E2E (Playwright, Chromium, real API + PostgreSQL) | 8 passed |
| Live pipeline smoke (API → orchestrator → scanner sandbox → record → findings) | HTTP scan of a LAN lab target created 6 findings; re-scan deduplicated all 6; triage applied |
| Ruff / mypy strict / ESLint strict / tsc | clean |
| Real ZAP and Nuclei runs, scanner image build, compose, Trivy | CI only (the development host does not run third-party scanner binaries) |

The Nuclei test drives the real egress guard: while the fake tool "runs", it
sends a request through the configured proxy to `169.254.169.254` and the test
asserts the guard refused it and recorded the denial in the evidence.

## Phase 4 results (local run 2026-11-11)

| Suite | Result |
|-------|--------|
| Security engine (scope + scanner adapters with recorded fixtures and local TLS/HTTP servers) | 201 passed, 1 skipped (real Nmap binary not installed locally; runs where `nmap` exists) |
| Backend full suite (unit + integration + engine + workers, PostgreSQL 16 local) | 403 passed; the 2 real-Redis tests also pass against a `fakeredis` TCP server; coverage 96% |
| Frontend (Vitest) | 48 passed |
| E2E (Playwright, Chromium, real API + PostgreSQL) | 8 passed (scan configuration and emergency stop included; no scan is launched against public hosts) |
| Real pipeline smoke (API → orchestrator worker → scanner sandbox worker → record) | HTTP scan of a LAN lab target completed with pinned IP and fingerprints; cancel and emergency stop verified against live workers |
| Ruff / mypy strict / ESLint strict / tsc / Bandit | clean |
| Docker build (scanner image), compose smoke, Trivy, real-Redis tests | CI only |

Scan tests never contact third parties: CT lookups use `httpx.MockTransport`
fixtures, DNS uses fake resolvers, TLS/HTTP scanners run against servers bound to
`127.0.0.1`, and Nmap parsing uses a recorded XML document.

## Phase 3 results (local run 2026-11-11)

| Suite | Result |
|-------|--------|
| Security engine (scope parsing, policy, decisions, DNS) | 139 passed |
| Backend full suite (unit + integration + engine, PostgreSQL 16 local) | 316 passed, 2 deselected (need real Redis), coverage 97% |
| Frontend (Vitest) | 43 passed |
| E2E (Playwright, Chromium, real API + PostgreSQL) | 8 passed |
| Ruff / mypy strict / ESLint strict / tsc / Bandit | clean |
| Docker build, compose smoke, Trivy, real-Redis tests | CI only |

## Phase 1 results (2026-11-10)

Backend 43 passed (96% coverage), frontend 15, E2E 2; all static and security checks clean.
