"""Risk model: determinism, factor accounting, weights validation, posture, EPSS."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from sentinelx_security.intel.epss import fetch_epss, parse_epss
from sentinelx_security.intel.nvd import IntelError
from sentinelx_security.risk import (
    MODEL_VERSION,
    RiskInputs,
    RiskWeights,
    WeightsError,
    band_for,
    posture,
    score,
)

NOW = datetime(2026, 11, 12, tzinfo=UTC)
W = RiskWeights()
FIXTURES = Path(__file__).parent / "fixtures"


def test_factors_add_up_to_the_score() -> None:
    result = score(
        RiskInputs(
            severity="critical",
            confidence="tentative",
            cvss_score=9.8,
            kev=True,
            epss=0.5,
            asset_criticality="high",
            asset_exposure="external",
            first_seen_at=NOW - timedelta(days=45),
        ),
        W,
        NOW,
    )
    # 98 x 0.8 x 1.15 x 1.0 = 90.16; + 20 KEV + 7.5 EPSS + 3 age -> clamped to 100.
    assert result.score == 100.0
    assert result.band == "critical"
    assert round(sum(f.points for f in result.factors), 1) == result.score
    names = [f.name for f in result.factors]
    assert names == [
        "base",
        "confidence",
        "asset_criticality",
        "asset_exposure",
        "known_exploited",
        "exploit_prediction",
        "exposure_window",
        "clamp",
    ]
    assert result.model_version == MODEL_VERSION
    assert result.weights["kev_points"] == 20.0
    assert result.explanation.startswith("Critical risk (100/100): starts at 98 from CVSS 9.8")


def test_unscored_findings_use_severity_defaults() -> None:
    low = score(RiskInputs(severity="low", confidence="firm"), W, NOW)
    assert low.score == 27.0  # 30 x 1.0 x 1.0 x 0.9 (unknown exposure)
    assert low.band == "low"
    info = score(RiskInputs(severity="info", confidence="firm", asset_exposure="internal"), W, NOW)
    assert info.score == 3.8
    assert info.band == "info"


def test_score_is_deterministic_and_monotonic() -> None:
    inputs = RiskInputs(severity="medium", confidence="firm", cvss_score=5.0)
    assert score(inputs, W, NOW) == score(inputs, W, NOW)
    base = score(inputs, W, NOW).score
    for stronger in (
        RiskInputs(severity="medium", confidence="confirmed", cvss_score=5.0),
        RiskInputs(severity="medium", confidence="firm", cvss_score=5.0, kev=True),
        RiskInputs(severity="medium", confidence="firm", cvss_score=5.0, epss=0.9),
        RiskInputs(
            severity="medium", confidence="firm", cvss_score=5.0, asset_criticality="critical"
        ),
        RiskInputs(severity="medium", confidence="firm", cvss_score=5.0, asset_exposure="external"),
        RiskInputs(
            severity="medium",
            confidence="firm",
            cvss_score=5.0,
            first_seen_at=NOW - timedelta(days=120),
        ),
    ):
        assert score(stronger, W, NOW).score > base


def test_weights_validation() -> None:
    custom = RiskWeights.from_mapping({"kev_points": 30, "exposure_internal": 0.5})
    assert custom.kev_points == 30.0
    for bad, message in (
        ({"kev_points": 500}, "between"),
        ({"severity_critical": 0}, "between"),  # findings cannot be hidden by zeroing
        ({"nope": 1}, "Unknown"),
        ({"kev_points": "10"}, "number"),
        ({"kev_points": True}, "number"),
        ({"age_30_days_points": 20, "age_90_days_points": 5}, ">="),
    ):
        with pytest.raises(WeightsError, match=message):
            RiskWeights.from_mapping(bad)


def test_bands_and_posture() -> None:
    assert [band_for(v) for v in (95, 70, 45, 20, 5)] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]
    assert posture([]) == {
        "score": 0.0,
        "band": "info",
        "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "active": 0,
    }
    single = posture([90])
    assert single["score"] == 90.0
    crowded = posture([90, 85, 80, 75, 70, 2, 1])
    assert crowded["score"] == 93.9  # 90 + 10 x 0.5 x mean(85, 80, 75, 70)/100
    assert crowded["counts"]["critical"] == 3
    noise = posture([90] + [1] * 100)
    assert 90 <= noise["score"] < 90.1  # noise neither drowns nor inflates the worst issue
    assert posture([10, 90])["score"] >= 90  # never below the worst issue


def test_epss_parsing_and_fetching() -> None:
    payload = json.loads((FIXTURES / "epss_sample.json").read_text())
    scores = parse_epss(payload)
    assert scores["CVE-2021-41773"].probability == pytest.approx(0.99992)
    assert (
        parse_epss(
            {"data": [{"cve": "bad", "epss": "2"}, "x", {"cve": "CVE-2020-0001", "epss": "nan%"}]}
        )
        == {}
    )


async def test_epss_client_batches_and_reports_errors() -> None:
    seen: list[str] = []
    payload = json.loads((FIXTURES / "epss_sample.json").read_text())

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params["cve"])
        return httpx.Response(200, json=payload)

    ids = [f"CVE-2020-{n:05d}" for n in range(150)] + ["CVE-2021-41773", "garbage"]
    result = await fetch_epss(ids, transport=httpx.MockTransport(handler), min_interval=0)
    assert len(seen) == 2
    assert len(seen[0].split(",")) == 100
    assert "garbage" not in ",".join(seen)
    assert "CVE-2021-41773" in result

    with pytest.raises(IntelError):
        await fetch_epss(
            ["CVE-2021-41773"],
            transport=httpx.MockTransport(lambda _request: httpx.Response(503)),
            min_interval=0,
        )
