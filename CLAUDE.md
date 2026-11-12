# SentinelX — guide for Claude

Attack Surface Management / vulnerability assessment platform for **authorized** targets only.
Never add exploitation, brute force, DoS, evasion or stealth features (see `docs/SCANNING_POLICY.md`).

## Read this first, read the rest only when needed

Do not read whole docs up front. Open the specific doc only when the task touches it:

| Topic | Doc |
|---|---|
| Module boundaries, ADRs | `docs/ARCHITECTURE.md` |
| Tables, migrations | `docs/DATABASE.md` |
| Endpoints, error format | `docs/API.md` |
| Auth, RBAC, CSRF, tokens | `docs/AUTHENTICATION.md` |
| Scope engine, allowed scans | `docs/SCANNING_POLICY.md` |
| Test layout, markers | `docs/TESTING.md` |
| Phases and what is next | `docs/ROADMAP.md` |

Prefer LSP navigation (go-to-definition, references) and `grep` over reading full files.

## Layout (uv workspace, Python 3.12)

- `apps/api/app/` — FastAPI modular monolith: `api/v1/endpoints` → `services` → `repositories` → `models`; `schemas` (Pydantic), `core/config.py` (settings, `SENTINELX_` env prefix), `core/security`, `middleware`, `dependencies`. Alembic in `apps/api/migrations`.
- `workers/sentinelx_workers/` — Celery (`celery_app.py`, `scanner_app.py`, `tasks/`).
- `security-engine/sentinelx_security/` — scope engine (`scope/`), egress guard, scanners (ZAP, Nuclei, Nmap, TLS, DNS…), findings, threat intel (`intel/`).
- `apps/web/` — React 19 + Vite + TS, pnpm. `src/features/*` per domain; Zod validates every API response.
- `infrastructure/docker`, `docker-compose.yml`, `.github/workflows/{ci,containers}.yml`.

## Commands

```bash
make check              # lint + typecheck + unit tests + security audits (what CI runs without infra)
uv run pytest path/to/test_x.py -q    # run only what you changed first
uv run pytest -m integration          # needs SENTINELX_DATABASE_URL (postgresql+asyncpg://) + SENTINELX_REDIS_URL
make format             # ruff fix + format
make typecheck          # mypy --strict + tsc
cd apps/web && pnpm test | pnpm lint | pnpm typecheck
```

Pytest runs with `filterwarnings = error` and `-m "not integration"` by default. Integration tests TRUNCATE the target DB.

## Dev host constraints (this machine)

- **No Docker.** Compose, Trivy and image builds are verified only in CI — report them as "not run locally".
- Postgres: `pgserver` wheel in a scratchpad venv (port 54329, TCP). Scratchpad is wiped per session → reinstall.
- Redis: `fakeredis` in tests; `fakeredis.TcpFakeServer` (+ `fakeredis[lua]`) as a local Redis for E2E/Celery.
- Node 22.19: React Router 8 and jsdom ≥30 are blocked; TypeScript pinned to 6.0.x.
- The scope engine always blocks loopback; for live scan smoke tests use the LAN IP via `SENTINELX_SCOPE_LAB_NETWORKS`.
- Fixtures: use `*.example.com` emails (email-validator rejects `.local`). Tests never hit public third-party hosts.
- No `gh` CLI: the user opens PRs; check CI through the public GitHub Actions API.

## Conventions

- Python: Ruff, mypy `--strict`, absolute imports, typed public functions, no `print`, no bare `except`, no `assert` for validation, no shell with untrusted input.
- Every schema change = Alembic revision with clean upgrade/downgrade; `alembic check` must pass.
- Conventional Commits; branches `feat/<topic>` from `main`. Phases ship as **stacked branches** (phase-N on top of phase-N-1); fixes on a lower phase are merged upward.
- Each phase stops for explicit user approval before the next one starts.
- Update the relevant `docs/` file in the same change. Docs and code in English; reply to the user in Portuguese (pt-BR).
