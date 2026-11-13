---
name: local-infra
description: Start (or stop) a local PostgreSQL 16 and Redis for SentinelX on this Docker-less host, for integration tests, `make test-all`, live API/worker runs or E2E. Use before `pytest -m integration`, `make dev-api`, `make dev-worker`, or whenever a command needs SENTINELX_DATABASE_URL / SENTINELX_REDIS_URL.
---

# Local infrastructure (no Docker)

PostgreSQL comes from the `pgserver` wheel; Redis is `fakeredis.TcpFakeServer` (with Lua, so Celery works).
Both live in the session scratchpad, which is wiped between sessions — always run the script, never assume they are up.

## Start

```bash
STATE=<scratchpad>/infra                       # use this session's scratchpad path
.claude/skills/local-infra/scripts/start.sh "$STATE" [db-name]   # default db: sentinelx_test
source "$STATE/infra.env"
```

- Idempotent: reuses venv/cluster, skips servers already listening, **drops and recreates** the database.
- Ports: Postgres `127.0.0.1:54329` (user `postgres`, trust auth, TCP only), Redis `127.0.0.1:6390`.
- `infra.env` sets `SENTINELX_ENVIRONMENT=test`, `DATABASE_URL`, `REDIS_URL`, a random `SECRET_KEY`, `ALLOWED_HOSTS`.
- Takes ~2 s when the uv cache is warm; first run downloads pgserver (~1 min).

## Use

```bash
uv run pytest -m integration -q        # 127 tests, ~35 s; real-Redis tests pass against fakeredis
uv run pytest -m "" --cov              # full suite + coverage gate (= make test-all)
```

For a live API/worker or E2E, use a separate database (`start.sh "$STATE" sentinelx_e2e`) and add to the env:
`SENTINELX_ENVIRONMENT=development`, `SENTINELX_COOKIE_SECURE=false`, `SENTINELX_LOG_JSON=false`,
`SENTINELX_RATE_LIMIT_LOGIN_PER_MINUTE=1000`. Run migrations with
`uv run alembic -c apps/api/alembic.ini upgrade head` before starting uvicorn.

## Stop

```bash
.claude/skills/local-infra/scripts/stop.sh "$STATE"
```

## Gotchas

- Integration tests TRUNCATE the target DB — never point them at anything but these throwaway databases.
- Scans: the scope engine always blocks loopback; for live scanner smoke tests set
  `SENTINELX_SCOPE_LAB_NETWORKS` to the LAN IP's network and target the LAN IP.
- Never `pkill -f` a pattern that also appears in your own shell command; use `stop.sh` (pid file / pg_ctl).
- Logs: `$STATE/pg.log`, `$STATE/redis.log`.
