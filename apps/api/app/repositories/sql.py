"""Small SQL helpers shared by repositories."""

from __future__ import annotations

LIKE_ESCAPE = "\\"


def contains_pattern(term: str) -> str:
    """Build a case-normalized ``LIKE`` pattern with wildcards in ``term`` escaped."""
    escaped = (
        term.strip()
        .lower()
        .replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", f"{LIKE_ESCAPE}%")
        .replace("_", f"{LIKE_ESCAPE}_")
    )
    return f"%{escaped}%"
