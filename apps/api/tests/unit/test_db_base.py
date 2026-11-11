from __future__ import annotations

from datetime import UTC

from app.db.base import NAMING_CONVENTION, Base, utcnow


def test_metadata_uses_deterministic_naming_convention() -> None:
    assert Base.metadata.naming_convention == NAMING_CONVENTION


def test_utcnow_is_timezone_aware_utc() -> None:
    assert utcnow().tzinfo is UTC
