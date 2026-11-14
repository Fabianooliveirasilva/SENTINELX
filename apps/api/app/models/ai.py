"""AI analyses (Phase 9): advisory output stored apart from evidence, with provenance."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin, utcnow

AI_KINDS = (
    "finding_analysis",
    "scan_summary",
    "scan_comparison",
    "executive_summary",
    "technical_summary",
)
AI_STATUSES = ("pending", "running", "completed", "failed")
AI_PROVIDERS = ("anthropic", "deterministic")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(repr(v) for v in values) + ")"


class AIAnalysis(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "ai_analyses"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))
    # finding / scan_job / project; comparisons keep the second scan in `parameters`.
    subject_type: Mapped[str] = mapped_column(String(16))
    subject_id: Mapped[uuid.UUID] = mapped_column()
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    status: Mapped[str] = mapped_column(
        String(16), default="pending", server_default=text("'pending'")
    )
    provider: Mapped[str | None] = mapped_column(String(16))
    model: Mapped[str | None] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(64))
    # sha256 of kind + prompt version + model + minimized context: identical
    # requests reuse a recent result instead of paying for it twice.
    input_hash: Mapped[str] = mapped_column(String(64))
    context_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    output: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    warnings: Mapped[list[str]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    fallback_reason: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(String(300))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    output_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0, server_default=text("0"))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_by_email: Mapped[str | None] = mapped_column(String(320))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_in("kind", AI_KINDS), name="kind"),
        CheckConstraint(_in("status", AI_STATUSES), name="status"),
        CheckConstraint(f"provider IS NULL OR {_in('provider', AI_PROVIDERS)}", name="provider"),
        Index("ix_ai_analyses_project_id_created_at", "project_id", "created_at"),
        Index("ix_ai_analyses_project_id_subject_id_kind", "project_id", "subject_id", "kind"),
        Index("ix_ai_analyses_input_hash", "input_hash"),
    )
