"""Deterministic, versioned and explainable risk scoring.

Score (0-100) for one finding::

    base        = CVSS base score x 10, or a severity default when unscored
    adjusted    = base x confidence x asset criticality x asset exposure
    score       = clamp(adjusted + KEV points + EPSS x EPSS points + age points)

Every step is reported as a :class:`Factor` with the points it contributed and a
plain-language reason, so a score can always be reproduced and explained. The
model version is stored with every score; changing the formula requires a new
``MODEL_VERSION``. Weights are data (validated, admin-configurable) and are
stored with each score too.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from typing import Any, Final

MODEL_VERSION: Final = "1.0.0"
BANDS: Final = (("critical", 80.0), ("high", 60.0), ("medium", 40.0), ("low", 15.0))


class WeightsError(ValueError):
    pass


def _range(low: float, high: float) -> dict[str, float]:
    return {"min": low, "max": high}


WEIGHT_BOUNDS: Final[Mapping[str, Mapping[str, float]]] = {
    **{f"severity_{s}": _range(1, 100) for s in ("critical", "high", "medium", "low", "info")},
    **{f"confidence_{c}": _range(0.1, 2) for c in ("tentative", "firm", "confirmed")},
    **{f"criticality_{c}": _range(0.1, 3) for c in ("low", "medium", "high", "critical")},
    **{f"exposure_{e}": _range(0.1, 2) for e in ("external", "internal", "unknown")},
    "kev_points": _range(0, 50),
    "epss_points": _range(0, 50),
    "age_30_days_points": _range(0, 25),
    "age_90_days_points": _range(0, 25),
}


@dataclass(frozen=True, slots=True)
class RiskWeights:
    """Tunable parameters. Bounds are enforced by :meth:`validate`."""

    severity_critical: float = 95.0
    severity_high: float = 80.0
    severity_medium: float = 55.0
    severity_low: float = 30.0
    severity_info: float = 5.0
    confidence_tentative: float = 0.8
    confidence_firm: float = 1.0
    confidence_confirmed: float = 1.1
    criticality_low: float = 0.7
    criticality_medium: float = 1.0
    criticality_high: float = 1.15
    criticality_critical: float = 1.3
    exposure_external: float = 1.0
    exposure_internal: float = 0.75
    exposure_unknown: float = 0.9
    kev_points: float = 20.0
    epss_points: float = 15.0
    age_30_days_points: float = 3.0
    age_90_days_points: float = 7.0

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RiskWeights:
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise WeightsError(f"Unknown weight(s): {', '.join(sorted(unknown))}.")
        values: dict[str, float] = {}
        for name, value in data.items():
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise WeightsError(f"{name} must be a number.")
            values[name] = float(value)
        weights = cls(**values)
        weights.validate()
        return weights

    def validate(self) -> None:
        for name, bounds in WEIGHT_BOUNDS.items():
            value = getattr(self, name)
            if not bounds["min"] <= value <= bounds["max"]:
                raise WeightsError(
                    f"{name} must be between {bounds['min']:g} and {bounds['max']:g}."
                )
        if self.age_90_days_points < self.age_30_days_points:
            raise WeightsError("age_90_days_points must be >= age_30_days_points.")

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RiskInputs:
    severity: str
    confidence: str
    cvss_score: float | None = None
    kev: bool = False
    epss: float | None = None
    asset_criticality: str = "medium"
    asset_exposure: str = "unknown"
    first_seen_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Factor:
    name: str
    value: str
    effect: str
    points: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "effect": self.effect,
            "points": round(self.points, 1),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RiskResult:
    score: float
    band: str
    factors: tuple[Factor, ...]
    explanation: str
    model_version: str = MODEL_VERSION
    weights: Mapping[str, float] = field(default_factory=dict)

    def factors_dict(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.factors]


def band_for(score: float) -> str:
    for name, threshold in BANDS:
        if score >= threshold:
            return name
    return "info"


def score(inputs: RiskInputs, weights: RiskWeights, now: datetime) -> RiskResult:
    factors: list[Factor] = []

    if inputs.cvss_score is not None:
        base = max(0.0, min(10.0, inputs.cvss_score)) * 10
        factors.append(
            Factor("base", f"CVSS {inputs.cvss_score:g}", "base", base, "CVSS base score x 10.")
        )
    else:
        base = float(getattr(weights, f"severity_{inputs.severity}", weights.severity_medium))
        factors.append(
            Factor(
                "base",
                f"severity {inputs.severity}",
                "base",
                base,
                "No CVSS score; default for the finding's severity.",
            )
        )

    value = base
    for name, key, reason in (
        ("confidence", f"confidence_{inputs.confidence}", "How certain the finding is."),
        (
            "asset_criticality",
            f"criticality_{inputs.asset_criticality}",
            "Business importance of the affected asset.",
        ),
        (
            "asset_exposure",
            f"exposure_{inputs.asset_exposure}",
            "Whether the asset is reachable from the internet.",
        ),
    ):
        multiplier = float(getattr(weights, key, 1.0))
        new_value = value * multiplier
        factors.append(
            Factor(
                name,
                key.split("_", 1)[1],
                f"x {multiplier:g}",
                new_value - value,
                reason,
            )
        )
        value = new_value

    if inputs.kev:
        factors.append(
            Factor(
                "known_exploited",
                "CISA KEV",
                f"+ {weights.kev_points:g}",
                weights.kev_points,
                "Listed in CISA's Known Exploited Vulnerabilities catalog.",
            )
        )
        value += weights.kev_points
    if inputs.epss is not None:
        probability = max(0.0, min(1.0, inputs.epss))
        points = probability * weights.epss_points
        factors.append(
            Factor(
                "exploit_prediction",
                f"EPSS {probability:.3f}",
                f"+ EPSS x {weights.epss_points:g}",
                points,
                "Probability of exploitation in the next 30 days (FIRST EPSS).",
            )
        )
        value += points
    if inputs.first_seen_at is not None:
        age_days = max(0, (now - inputs.first_seen_at).days)
        points = 0.0
        if age_days >= 90:
            points = weights.age_90_days_points
        elif age_days >= 30:
            points = weights.age_30_days_points
        if points:
            factors.append(
                Factor(
                    "exposure_window",
                    f"{age_days} days open",
                    f"+ {points:g}",
                    points,
                    "Long-lived issues have been exploitable for longer.",
                )
            )
            value += points

    final = round(max(0.0, min(100.0, value)), 1)
    if final != round(value, 1):
        factors.append(
            Factor("clamp", "0-100", "clamp", final - value, "Scores are bounded to 0-100.")
        )
    band = band_for(final)
    drivers = sorted((f for f in factors if f.name != "base"), key=lambda f: -abs(f.points))[:3]
    reasons = [f"{d.name.replace('_', ' ')} {d.points:+.1f}" for d in drivers if d.points]
    explanation = (
        f"{band.capitalize()} risk ({final:g}/100): starts at {base:g} from {factors[0].value}"
        + (f"; {', '.join(reasons)}" if reasons else "")
        + "."
    )
    return RiskResult(
        score=final,
        band=band,
        factors=tuple(factors),
        explanation=explanation,
        weights=weights.to_dict(),
    )


def posture(scores: Iterable[float]) -> dict[str, Any]:
    """Project posture from active finding scores.

    ``posture = worst + (100 - worst) x 0.5 x mean(next 4 worst) / 100``: never
    below the worst issue, raised when several serious issues coexist, and
    unaffected by long tails of informational noise.
    """
    ordered = sorted(scores, reverse=True)
    counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
    for value in ordered:
        counts[band_for(value)] += 1
    if not ordered:
        return {"score": 0.0, "band": "info", "counts": counts, "active": 0}
    worst = ordered[0]
    others = ordered[1:5]
    boost = (sum(others) / len(others)) / 100 if others else 0.0
    value = round(min(100.0, worst + (100 - worst) * 0.5 * boost), 1)
    return {"score": value, "band": band_for(value), "counts": counts, "active": len(ordered)}
