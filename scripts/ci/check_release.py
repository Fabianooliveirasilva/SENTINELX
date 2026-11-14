#!/usr/bin/env python3
"""Release consistency check: every version declaration must agree.

Compares the newest ``## [x.y.z]`` entry of CHANGELOG.md with the Python packages,
the web package and the API's default version; with a tag argument (``v1.2.3``) the
tag must match as well. Prints the changelog section for the release notes with
``--notes``.

Usage: check_release.py [vX.Y.Z] [--notes]
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
CHANGELOG_ENTRY = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)
PYPROJECTS = (
    "pyproject.toml",
    "apps/api/pyproject.toml",
    "workers/pyproject.toml",
    "security-engine/pyproject.toml",
)


def changelog_version(text: str) -> str | None:
    match = CHANGELOG_ENTRY.search(text)
    return match.group(1) if match else None


def changelog_section(text: str, version: str) -> str:
    start = re.search(rf"^## \[{re.escape(version)}\].*$", text, re.MULTILINE)
    if start is None:
        return ""
    rest = text[start.end() :]
    end = re.search(r"^## \[", rest, re.MULTILINE)
    return (rest[: end.start()] if end else rest).strip()


def declared_versions(root: Path) -> dict[str, str]:
    found = {
        path: tomllib.loads((root / path).read_text())["project"]["version"] for path in PYPROJECTS
    }
    found["apps/web/package.json"] = json.loads((root / "apps/web/package.json").read_text())[
        "version"
    ]
    config = (root / "apps/api/app/core/config.py").read_text()
    match = re.search(r'^\s+version: str = "([^"]+)"', config, re.MULTILINE)
    found["apps/api/app/core/config.py"] = match.group(1) if match else "<missing>"
    return found


def problems_for(root: Path, tag: str | None) -> tuple[list[str], str | None]:
    changelog = (root / "CHANGELOG.md").read_text()
    expected = changelog_version(changelog)
    problems: list[str] = []
    if expected is None:
        return ["CHANGELOG.md has no '## [x.y.z]' entry"], None
    for where, version in declared_versions(root).items():
        if not SEMVER.match(version) or version != expected:
            problems.append(f"{where}: version {version!r} != CHANGELOG {expected!r}")
    if tag is not None and tag != f"v{expected}":
        problems.append(f"tag {tag!r} != v{expected} (newest CHANGELOG entry)")
    if not changelog_section(changelog, expected):
        problems.append(f"CHANGELOG entry {expected} is empty")
    return problems, expected


def main(argv: list[str]) -> int:
    tag = next((a for a in argv[1:] if not a.startswith("--")), None)
    problems, expected = problems_for(ROOT, tag)
    if problems:
        for problem in problems:
            print(f"release: {problem}", file=sys.stderr)
        return 1
    if "--notes" in argv and expected:
        print(changelog_section((ROOT / "CHANGELOG.md").read_text(), expected))
    else:
        print(f"release: all versions are {expected}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
