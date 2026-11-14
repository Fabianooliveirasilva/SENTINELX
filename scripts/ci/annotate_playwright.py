#!/usr/bin/env python3
"""Annotate failed Playwright tests from a JSON report (job logs need admin access).

Usage: annotate_playwright.py <report.json>
One annotation lists every failed test with the first lines of its error. Error text
is cut and ANSI colours removed; no request bodies or cookies are part of it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_CHARS = 3500
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def failures(report: dict[str, Any]) -> list[str]:
    rows: list[str] = []

    def walk(suite: dict[str, Any], trail: list[str]) -> None:
        here = [*trail, suite["title"]] if suite.get("title") else trail
        for spec in suite.get("specs", []):
            for test in spec.get("tests", []):
                results = test.get("results") or []
                if not results or test.get("status") in ("expected", "skipped"):
                    continue
                error = (results[-1].get("error") or {}).get("message", "") or ""
                lines = [ln.strip() for ln in ANSI.sub("", error).splitlines() if ln.strip()]
                where = f"{spec.get('file')}:{spec.get('line')}"
                rows.append(f"{' > '.join([*here, spec['title']])} ({where})")
                rows.extend(f"    {ln[:200]}" for ln in lines[:6])
        for child in suite.get("suites", []):
            walk(child, here)

    for suite in report.get("suites", []):
        walk(suite, [])
    return rows


def main(path: str) -> int:
    target = Path(path)
    if not target.is_file() or not target.stat().st_size:
        return 0
    rows = failures(json.loads(target.read_text(encoding="utf-8")))
    if rows:
        text = (
            "\n".join(rows)[:MAX_CHARS].replace("%", "%25").replace("\r", "").replace("\n", "%0A")
        )
        print(f"::error title=playwright failures::{text}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
