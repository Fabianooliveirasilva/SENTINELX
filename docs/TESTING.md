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

## Latest results (Phase 3, local run 2026-11-11)

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
