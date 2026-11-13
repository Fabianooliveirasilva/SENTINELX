#!/usr/bin/env bash
# Start a throwaway PostgreSQL 16 (pgserver wheel) and a fakeredis TCP server for
# SentinelX integration/E2E tests on a host without Docker.
#
# Usage: start.sh <state-dir> [db-name]
#   <state-dir>  scratch directory that holds the venv, data dir, logs and env file
#   [db-name]    database to (re)create, default: sentinelx_test
#
# Idempotent: reuses the venv/cluster if present, skips servers already listening.
# Writes <state-dir>/infra.env — `source` it before running pytest/uvicorn/celery.
set -euo pipefail

STATE="${1:?usage: start.sh <state-dir> [db-name]}"
DB="${2:-sentinelx_test}"
PG_PORT=54329
REDIS_PORT=6390
UV="${UV:-$HOME/.local/bin/uv}"
REPO="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

mkdir -p "$STATE"
cd "$STATE"

# --- PostgreSQL -----------------------------------------------------------
if [ ! -x pgenv/bin/python ]; then
  "$UV" venv -q pgenv --python 3.12
  "$UV" pip install -q --python pgenv/bin/python pgserver
fi
B="$(find "$STATE/pgenv" -type d -path '*pginstall/bin' | head -1)"
[ -n "$B" ] || { echo "pgserver binaries not found" >&2; exit 1; }

if [ ! -f pgdata/PG_VERSION ]; then
  "$B/initdb" -D pgdata -U postgres --auth=trust -E UTF8 >/dev/null
fi
if ! "$B/pg_isready" -q -h 127.0.0.1 -p "$PG_PORT"; then
  "$B/pg_ctl" -D pgdata -l pg.log -w \
    -o "-p $PG_PORT -k '' -c listen_addresses=127.0.0.1 -c shared_buffers=32MB" start >/dev/null
fi
"$B/psql" -h 127.0.0.1 -p "$PG_PORT" -U postgres -qc "drop database if exists $DB" -c "create database $DB"

# --- Redis (fakeredis TCP, with Lua for Celery) ----------------------------
if ! (exec 3<>"/dev/tcp/127.0.0.1/$REDIS_PORT") 2>/dev/null; then
  nohup "$UV" run --project "$REPO" --with 'fakeredis[lua]' python -c \
    "from fakeredis import TcpFakeServer; TcpFakeServer(('127.0.0.1', $REDIS_PORT), server_type='redis').serve_forever()" \
    >redis.log 2>&1 &
  echo $! >redis.pid
  for _ in $(seq 1 30); do
    (exec 3<>"/dev/tcp/127.0.0.1/$REDIS_PORT") 2>/dev/null && break
    sleep 0.5
  done
fi

# --- env file ------------------------------------------------------------
SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
cat >infra.env <<EOF
export SENTINELX_ENVIRONMENT=test
export SENTINELX_DATABASE_URL=postgresql+asyncpg://postgres@127.0.0.1:$PG_PORT/$DB
export SENTINELX_REDIS_URL=redis://127.0.0.1:$REDIS_PORT/0
export SENTINELX_SECRET_KEY=$SECRET
export SENTINELX_ALLOWED_HOSTS=localhost,127.0.0.1,testserver
EOF

echo "postgres: 127.0.0.1:$PG_PORT/$DB  redis: 127.0.0.1:$REDIS_PORT"
echo "env:      source $STATE/infra.env"
