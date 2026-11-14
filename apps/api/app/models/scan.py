"""Scan jobs, their normalized observations and bounded evidence."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin, utcnow

SCAN_STATUSES = ("pending", "queued", "running", "completed", "failed", "cancelled")
ACTIVE_STATUSES = ("pending", "queued", "running")


class ScanResult(UUIDPrimaryKeyMixin, Base):
    """One normalized observation (open port, TLS endpoint, DNS record, …)."""

    __tablename__ = "scan_results"

    scan_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(64))
    key: Mapped[str] = mapped_column(String(512))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    attention: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), default=list, server_default=text("'{}'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        Index("ix_scan_results_scan_job_id", "scan_job_id"),
        Index("ix_scan_results_project_id_kind", "project_id", "kind"),
    )


class ScanEvidence(UUIDPrimaryKeyMixin, Base):
    """Raw, size-bounded tool output kept for traceability (untrusted content)."""

    __tablename__ = "scan_evidence"

    scan_job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    label: Mapped[str] = mapped_column(String(200))
    media_type: Mapped[str] = mapped_column(String(100))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )

    __table_args__ = (Index("ix_scan_evidence_scan_job_id", "scan_job_id"),)


class ScanJob(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "scan_jobs"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    scanner: Mapped[str] = mapped_column(String(32))
    profile: Mapped[str] = mapped_column(String(32))
    technique: Mapped[str] = mapped_column(String(16))
    target: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    executor_task_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    scope_decision: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    pinned_addresses: Mapped[list[str]] = mapped_column(
        ARRAY(String(45)), default=list, server_default=text("'{}'")
    )
    tool_versions: Mapped[dict[str, str]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )

    results: Mapped[list[ScanResult]] = relationship(
        lazy="raise", order_by=ScanResult.kind, cascade="all, delete-orphan"
    )
    evidence: Mapped[list[ScanEvidence]] = relationship(lazy="raise", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint(
            "status IN (" + ", ".join(repr(s) for s in SCAN_STATUSES) + ")", name="status"
        ),
        Index("ix_scan_jobs_project_id_created_at", "project_id", "created_at"),
        Index("ix_scan_jobs_project_id_status", "project_id", "status"),
        Index("ix_scan_jobs_asset_id", "asset_id"),
    )
