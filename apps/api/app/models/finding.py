"""Findings: deduplicated security issues with lifecycle and evidence trail."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow

SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("tentative", "firm", "confirmed")
FINDING_STATUSES = ("open", "acknowledged", "false_positive", "accepted_risk", "resolved")
# Statuses an analyst has closed on purpose: re-observation does not reopen them.
SUPPRESSED_STATUSES = ("false_positive", "accepted_risk")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(repr(v) for v in values) + ")"


class FindingOccurrence(UUIDPrimaryKeyMixin, Base):
    """One sighting of a finding in a scan, with the observation that produced it."""

    __tablename__ = "finding_occurrences"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    observation: Mapped[dict[str, Any]] = mapped_column(JSONB)

    __table_args__ = (Index("ix_finding_occurrences_finding_id", "finding_id", "observed_at"),)


class FindingStatusChange(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "finding_status_changes"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    from_status: Mapped[str | None] = mapped_column(String(32))
    to_status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    changed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    changed_by_email: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )

    __table_args__ = (Index("ix_finding_status_changes_finding_id", "finding_id", "created_at"),)


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(200))
    ruleset_version: Mapped[str] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    remediation: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    location: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    cwe: Mapped[int | None] = mapped_column(Integer)
    references: Mapped[list[str]] = mapped_column(
        ARRAY(String(500)), default=list, server_default=text("'{}'")
    )
    status: Mapped[str] = mapped_column(String(32), default="open", server_default=text("'open'"))
    status_reason: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    last_profile: Mapped[str] = mapped_column(String(32))
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"))

    occurrences: Mapped[list[FindingOccurrence]] = relationship(
        lazy="raise",
        order_by=FindingOccurrence.observed_at.desc(),
        cascade="all, delete-orphan",
    )
    history: Mapped[list[FindingStatusChange]] = relationship(
        lazy="raise",
        order_by=FindingStatusChange.created_at.desc(),
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity"),
        CheckConstraint(_in("confidence", CONFIDENCES), name="confidence"),
        CheckConstraint(_in("status", FINDING_STATUSES), name="status"),
        Index("ix_findings_project_id_status_severity", "project_id", "status", "severity"),
        Index("ix_findings_asset_id", "asset_id"),
    )
