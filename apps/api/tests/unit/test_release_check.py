"""Release consistency checker."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[4]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_release", ROOT / "scripts/ci/check_release.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_release"] = module
    spec.loader.exec_module(module)
    return module


check = _load()


def test_repository_versions_agree() -> None:
    problems, version = check.problems_for(ROOT, None)
    assert problems == []
    assert version is not None
    assert check.problems_for(ROOT, f"v{version}")[0] == []


def test_mismatched_tag_and_versions_are_reported(tmp_path: Path) -> None:
    for relative in [
        *check.PYPROJECTS,
        "apps/web/package.json",
        "apps/api/app/core/config.py",
        "CHANGELOG.md",
    ]:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, target)
    _, version = check.problems_for(tmp_path, None)
    assert check.problems_for(tmp_path, "v0.0.1")[0] == [
        f"tag 'v0.0.1' != v{version} (newest CHANGELOG entry)"
    ]

    package = tmp_path / "apps/web/package.json"
    package.write_text(package.read_text().replace(f'"version": "{version}"', '"version": "9.9.9"'))
    problems, _ = check.problems_for(tmp_path, None)
    assert any("apps/web/package.json" in p for p in problems)

    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n")
    assert check.problems_for(tmp_path, None)[0] == ["CHANGELOG.md has no '## [x.y.z]' entry"]


def test_notes_are_the_newest_section() -> None:
    text = "# C\n\n## [Unreleased]\n\n## [1.2.0] — d\n\n### Added\n- a\n\n## [1.1.0] — d\n- b\n"
    assert check.changelog_version(text) == "1.2.0"
    assert check.changelog_section(text, "1.2.0") == "### Added\n- a"
    assert check.changelog_section(text, "9.9.9") == ""
