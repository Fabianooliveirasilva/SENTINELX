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

## Phase 1 results (local run, 2026-11-10)

| Suite | Result |
|-------|--------|
| Backend unit + API (pytest) | 43 passed, coverage 96% |
| Frontend (Vitest) | 15 passed |
| E2E (Playwright, local API + Vite, no DB/Redis → "Degraded" path) | 2 passed |
| Ruff / mypy strict / ESLint (strict type-checked) / tsc | clean |
| Bandit / Semgrep (280 rules) / Gitleaks / pip-audit / pnpm audit | 0 findings |
| Integration tests, `docker compose` smoke, Trivy | **Not run locally** (Docker unavailable on the development host); executed by CI |
