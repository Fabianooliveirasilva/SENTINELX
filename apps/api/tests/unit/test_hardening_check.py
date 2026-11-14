"""The hardening checker passes on the repository and fails on each regression."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[4]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_hardening", ROOT / "scripts/ci/check_hardening.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_hardening"] = module
    spec.loader.exec_module(module)
    return module


check = _load()
COMPOSE: dict[str, Any] = yaml.safe_load((ROOT / "docker-compose.yml").read_text())


def test_repository_compose_and_dockerfiles_pass() -> None:
    assert check.check_compose(COMPOSE) == []
    for dockerfile in (ROOT / "infrastructure/docker").glob("*.Dockerfile"):
        assert check.check_dockerfile(dockerfile) == [], dockerfile.name


def _mutated(mutate: Any) -> list[str]:
    compose = copy.deepcopy(COMPOSE)
    mutate(compose["services"], compose["networks"])
    return list[str](check.check_compose(compose))


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda s, _n: s["api"].pop("cap_drop"), "api: cap_drop must include ALL"),
        (lambda s, _n: s["worker"].update(read_only=False), "worker: read_only must be true"),
        (lambda s, _n: s["web"].update(security_opt=[]), "web: security_opt must include"),
        (lambda s, _n: s["api"].update(privileged=True), "api: privileged"),
        (lambda s, _n: s["api"].update(cap_add=["NET_ADMIN"]), "api: cap_add"),
        (lambda s, _n: s["api"].update(ports=["0.0.0.0:8000:8000"]), "must bind to 127.0.0.1"),
        (lambda s, _n: s["worker"].update(volumes=["/var/run/docker.sock:/x"]), "Docker socket"),
        (lambda s, _n: s["api"].update(network_mode="host"), "network_mode: host"),
        (
            lambda s, _n: s["worker"].update(networks=["backend", "scan-egress"]),
            "egress network scan-egress",
        ),
        (lambda _s, n: n["backend"].update(internal=False), "network backend must be internal"),
        (
            lambda s, _n: s["api"].update(networks=["backend", "frontend", "ai-egress"]),
            "frontend and an egress",
        ),
    ],
)
def test_regressions_are_detected(mutate: Any, expected: str) -> None:
    assert any(expected in problem for problem in _mutated(mutate))


def test_dockerfile_rules(tmp_path: Path) -> None:
    bad = tmp_path / "bad.Dockerfile"
    bad.write_text("FROM python:latest AS base\nADD https://example.com/x.tgz /x.tgz\nUSER root\n")
    problems = " ".join(check.check_dockerfile(bad))
    assert "must be pinned" in problems
    assert "remote ADD without --checksum" in problems
    assert "unprivileged user" in problems
    good = tmp_path / "good.Dockerfile"
    good.write_text(
        "ARG IMG=python:3.12-slim\nFROM ${IMG} AS build\nFROM build AS run\nUSER 10001:10001\n"
    )
    assert check.check_dockerfile(good) == []
