#!/usr/bin/env python3
"""Create a local .env from .env.example with cryptographically random secrets.

Refuses to overwrite an existing .env unless --force is given.

    python3 scripts/generate_env.py [--force] [--output PATH]
"""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / ".env.example"

# token_urlsafe only emits [A-Za-z0-9_-], which is safe inside connection URLs.
GENERATED = {
    "SENTINELX_SECRET_KEY": lambda: secrets.token_urlsafe(48),
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(24),
    "REDIS_PASSWORD": lambda: secrets.token_urlsafe(24),
}


def render(template: str) -> str:
    lines = []
    for line in template.splitlines():
        key, sep, _ = line.partition("=")
        if sep and key in GENERATED:
            line = f"{key}={GENERATED[key]()}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="overwrite an existing file")
    parser.add_argument("--output", type=Path, default=ROOT / ".env")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        print(f"{args.output} already exists; use --force to overwrite.", file=sys.stderr)
        return 1

    args.output.write_text(render(TEMPLATE.read_text(encoding="utf-8")), encoding="utf-8")
    args.output.chmod(0o600)
    print(f"Wrote {args.output} with freshly generated secrets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
