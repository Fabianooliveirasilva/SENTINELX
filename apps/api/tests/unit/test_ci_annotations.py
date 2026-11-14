"""CI helper: ZAP alerts are summarized, informational ones are dropped."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def test_zap_summary_keeps_low_and_above_most_severe_first() -> None:
    spec = importlib.util.spec_from_file_location(
        "annotate_failure", ROOT / "scripts/ci/annotate_failure.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["annotate_failure"] = module
    spec.loader.exec_module(module)
    report = {
        "site": [
            {
                "alerts": [
                    {
                        "name": "Info thing",
                        "riskcode": "0",
                        "riskdesc": "Informational (Low)",
                        "count": "3",
                    },
                    {
                        "name": "Missing header",
                        "riskcode": "1",
                        "riskdesc": "Low (Medium)",
                        "count": "2",
                    },
                    {
                        "name": "Exposed key",
                        "riskcode": "3",
                        "riskdesc": "High (High)",
                        "count": "1",
                    },
                ]
            }
        ]
    }
    assert module.summarize_zap(report) == [
        "High (High) | Exposed key | 1 instance(s)",
        "Low (Medium) | Missing header | 2 instance(s)",
    ]
