#!/usr/bin/env python3
"""Static container-hardening review of docker-compose.yml and the Dockerfiles.

Runs without Docker. Every rule is an invariant the project already claims in
docs/SECURITY.md; documented exceptions are listed explicitly below, so a new
service (or a regression) fails the build instead of silently weakening it.

Usage: check_hardening.py [compose-file] [dockerfile-dir]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

# Stock database images start as root, chown their data directory and drop to an
# unprivileged user themselves; they need a writable root FS and a few capabilities.
# Their isolation comes from the internal `backend` network. Revisit once the images
# can be run with `cap_drop: ALL` and a read-only FS in CI.
STOCK_IMAGE_EXCEPTIONS = {"postgres", "redis"}

# Networks with outbound internet access and the only services allowed on them.
EGRESS_NETWORKS = {
    "scan-egress": {"scanner", "scanner-zap"},
    "intel-egress": {"intel"},
    "notify-egress": {"notifier"},
    "ai-egress": {"ai"},
}
INTERNAL_NETWORKS = {"backend", "zap-net"}
LOOPBACK = ("127.0.0.1:", "[::1]:")
DOCKER_SOCKET = "docker.sock"


def _networks(service: dict[str, Any]) -> set[str]:
    nets = service.get("networks") or []
    return set(nets) if not isinstance(nets, dict) else set(nets.keys())


def check_compose(compose: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    services: dict[str, dict[str, Any]] = compose.get("services", {})
    networks: dict[str, Any] = compose.get("networks", {}) or {}

    for name, svc in services.items():
        if "no-new-privileges:true" not in (svc.get("security_opt") or []):
            problems.append(f"{name}: security_opt must include no-new-privileges:true")
        if name not in STOCK_IMAGE_EXCEPTIONS:
            if "ALL" not in (svc.get("cap_drop") or []):
                problems.append(f"{name}: cap_drop must include ALL")
            if svc.get("read_only") is not True:
                problems.append(f"{name}: read_only must be true")
        if svc.get("cap_add"):
            problems.append(f"{name}: cap_add is not allowed ({svc['cap_add']})")
        if svc.get("privileged"):
            problems.append(f"{name}: privileged containers are not allowed")
        for key in ("network_mode", "pid", "ipc", "userns_mode"):
            if svc.get(key) == "host":
                problems.append(f"{name}: {key}: host is not allowed")
        for volume in svc.get("volumes") or []:
            if DOCKER_SOCKET in str(volume):
                problems.append(f"{name}: the Docker socket must not be mounted")
        for port in svc.get("ports") or []:
            if not str(port).startswith(LOOPBACK):
                problems.append(f"{name}: published port {port!r} must bind to 127.0.0.1")

    for net, allowed in EGRESS_NETWORKS.items():
        for name, svc in services.items():
            if net in _networks(svc) and name not in allowed:
                problems.append(f"{name}: not allowed on egress network {net}")
    for net in INTERNAL_NETWORKS:
        if not (networks.get(net) or {}).get("internal"):
            problems.append(f"network {net} must be internal: true")
    for name, svc in services.items():
        reaches_internet = _networks(svc) & set(EGRESS_NETWORKS)
        if "frontend" in _networks(svc) and reaches_internet:
            problems.append(f"{name}: must not join both frontend and an egress network")
    return problems


_FROM = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)
_ARG = re.compile(r"^ARG\s+(\w+)=(\S*)")


def check_dockerfile(path: Path) -> list[str]:
    problems: list[str] = []
    args: dict[str, str] = {}
    stages: set[str] = set()
    last_user: str | None = None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if arg := _ARG.match(line):
            args[arg.group(1)] = arg.group(2)
        if m := _FROM.match(line):
            image = m.group(1)
            ref = re.sub(r"\$\{(\w+)\}", lambda v: args.get(v.group(1), ""), image)
            if m.group(2):
                stages.add(m.group(2))
            if ref == "scratch" or ref in stages:
                continue
            if "@sha256:" not in ref and (":" not in ref or ref.endswith(":latest")):
                problems.append(
                    f"{path.name}: base image {ref!r} must be pinned (tag or digest, not latest)"
                )
        if line.upper().startswith("USER "):
            last_user = line.split(None, 1)[1].strip()
        if line.upper().startswith("ADD ") and "http" in line and "--checksum" not in line:
            problems.append(f"{path.name}: remote ADD without --checksum")
    if last_user is None or last_user.split(":")[0] in {"root", "0"}:
        problems.append(
            f"{path.name}: the final USER must be an unprivileged user (got {last_user!r})"
        )
    return problems


def main(argv: list[str]) -> int:
    compose_path = Path(argv[1] if len(argv) > 1 else "docker-compose.yml")
    docker_dir = Path(argv[2] if len(argv) > 2 else "infrastructure/docker")
    problems = check_compose(yaml.safe_load(compose_path.read_text()))
    for dockerfile in sorted(docker_dir.glob("*.Dockerfile")):
        problems.extend(check_dockerfile(dockerfile))
    for problem in problems:
        print(f"hardening: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("hardening: compose and Dockerfiles satisfy every rule")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
