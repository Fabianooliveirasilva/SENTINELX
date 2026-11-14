#!/usr/bin/env python3
"""Emit CI diagnostics as GitHub annotations (readable without log access).

Usage:
  annotate_failure.py containers          # status + log tail of every container
  annotate_failure.py trivy <report.json> # fixable CRITICAL findings of a Trivy report
  annotate_failure.py file <title> <path>  # tail of a text file (e.g. captured command output)

Uses the plain Docker CLI (not compose) so it works even when the compose project
failed to start. Log lines are already redacted by the services' logging pipeline.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - fixed argument vectors, CI diagnostics only
import sys
from pathlib import Path

MAX_CHARS = 3500


def annotate(title: str, message: str) -> None:
    text = message[-MAX_CHARS:].replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    # Property values must also escape ':' and ',' or GitHub drops the annotation.
    safe_title = (
        title.replace("%", "%25").replace(":", "%3A").replace(",", "%2C").replace("\n", " ")
    )
    print(f"::error title={safe_title}::{text}")


def containers() -> None:
    listing = subprocess.run(  # nosec B603 B607 - fixed docker CLI argv
        ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    annotate("containers", listing or "no containers")
    for line in listing.splitlines():
        name, _, status = line.partition("\t")
        if "healthy)" in status and "unhealthy" not in status:
            continue
        if status.startswith("Exited (0)"):
            continue
        logs = subprocess.run(  # noqa: S603  # nosec B603 B607
            ["docker", "logs", "--tail", "60", name],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
        annotate(f"{name} ({status})", (logs.stdout + logs.stderr) or "no output")


def file_tail(title: str, path: str) -> None:
    target = Path(path)
    if target.is_file():
        annotate(title, target.read_text(encoding="utf-8", errors="replace") or "(empty)")


def trivy(path: str) -> None:
    report_path = Path(path)
    if not report_path.is_file() or not report_path.stat().st_size:
        file_tail(f"trivy error {report_path.name}", f"{path}.stderr")
        return
    report = json.loads(report_path.read_text(encoding="utf-8"))
    rows = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            if vuln.get("Severity") == "CRITICAL" and vuln.get("FixedVersion"):
                rows.append(
                    f"{result.get('Target')} | {vuln.get('PkgName')} {vuln.get('InstalledVersion')}"
                    f" -> {vuln.get('FixedVersion')} | {vuln.get('VulnerabilityID')}"
                )
    if rows:
        annotate(f"trivy {report.get('ArtifactName')}", "\n".join(sorted(set(rows))))


if __name__ == "__main__":
    if sys.argv[1] == "containers":
        containers()
    elif sys.argv[1] == "file":
        file_tail(sys.argv[2], sys.argv[3])
    else:
        trivy(sys.argv[2])
