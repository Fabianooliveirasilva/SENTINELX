"""Generated reports (Phase 10).

Content is stored in PostgreSQL (``bytea``, size-capped): application containers
have read-only filesystems and no object store, and a report must stay tied to
the project's access control and retention.
"""

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
    LargeBinary,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, deferred, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin, utcnow

REPORT_SCOPES = ("project", "scan")
REPORT_FORMATS = ("pdf", "json")
REPORT_STATUSES = ("pending", "running", "completed", "failed")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(repr(v) for v in values) + ")"


class Report(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "reports"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    scope: Mapped[str] = mapped_column(String(16))
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    format: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(String(200))
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    status: Mapped[str] = mapped_column(
        String(16), default="pending", server_default=text("'pending'")
    )
    schema_version: Mapped[str] = mapped_column(String(32))
    # Never loaded with listings: fetched only for downloads.
    content: Mapped[bytes | None] = deferred(mapped_column(LargeBinary))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    error: Mapped[str | None] = mapped_column(String(300))
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    generated_by_email: Mapped[str | None] = mapped_column(String(320))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_in("scope", REPORT_SCOPES), name="scope"),
        CheckConstraint(_in("format", REPORT_FORMATS), name="format"),
        CheckConstraint(_in("status", REPORT_STATUSES), name="status"),
        CheckConstraint("scope <> 'scan' OR scan_job_id IS NOT NULL", name="scan_scope"),
        Index("ix_reports_project_id_created_at", "project_id", "created_at"),
    )
