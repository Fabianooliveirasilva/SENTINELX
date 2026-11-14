"""CI helper: failed Playwright tests are summarized without ANSI noise."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
RED = "\x1b[31m"
RESET = "\x1b[0m"


def test_failures_are_listed_with_error_lines_only_for_failed_tests() -> None:
    spec = importlib.util.spec_from_file_location(
        "annotate_playwright", ROOT / "scripts/ci/annotate_playwright.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["annotate_playwright"] = module
    spec.loader.exec_module(module)
    report = {
        "suites": [
            {
                "title": "a.spec.ts",
                "specs": [
                    {
                        "title": "passes",
                        "file": "a.spec.ts",
                        "line": 3,
                        "tests": [{"status": "expected", "results": [{"status": "passed"}]}],
                    }
                ],
                "suites": [
                    {
                        "title": "group",
                        "specs": [
                            {
                                "title": "breaks",
                                "file": "a.spec.ts",
                                "line": 9,
                                "tests": [
                                    {
                                        "status": "unexpected",
                                        "results": [
                                            {
                                                "error": {
                                                    "message": RED
                                                    + "Expected: visible"
                                                    + RESET
                                                    + "\nReceived: hidden"
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    assert module.failures(report) == [
        "a.spec.ts > group > breaks (a.spec.ts:9)",
        "    Expected: visible",
        "    Received: hidden",
    ]
