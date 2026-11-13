#!/usr/bin/env bash
# Stop the servers started by start.sh. Usage: stop.sh <state-dir>
set -uo pipefail
STATE="${1:?usage: stop.sh <state-dir>}"
B="$(find "$STATE/pgenv" -type d -path '*pginstall/bin' 2>/dev/null | head -1)"
[ -n "$B" ] && [ -d "$STATE/pgdata" ] && "$B/pg_ctl" -D "$STATE/pgdata" -m fast stop >/dev/null 2>&1
[ -f "$STATE/redis.pid" ] && kill "$(cat "$STATE/redis.pid")" 2>/dev/null && rm -f "$STATE/redis.pid"
echo "stopped"
