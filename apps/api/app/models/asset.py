"""Assets (things that may be assessed) and their authorization records."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow

ASSET_TYPES = ("domain", "subdomain", "ip_address", "web_application", "api_endpoint", "service")
CRITICALITIES = ("low", "medium", "high", "critical")
EXPOSURES = ("external", "internal", "unknown")
ASSET_STATUSES = ("active", "archived")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class AssetAuthorization(UUIDPrimaryKeyMixin, Base):
    """Immutable record of permission to test an asset. Only revocation changes it."""

    __tablename__ = "asset_authorizations"

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    authorized_by: Mapped[str] = mapped_column(String(200))
    organization: Mapped[str] = mapped_column(String(200))
    reference: Mapped[str] = mapped_column(String(200))
    notes: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    allow_active: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    allow_intrusive: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    include_subdomains: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    ip_ranges: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), default=list, server_default=text("'{}'")
    )
    recorded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    revocation_reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint("valid_until > valid_from", name="valid_window"),
        CheckConstraint("NOT allow_intrusive OR allow_active", name="intrusive_requires_active"),
        Index("ix_asset_authorizations_asset_id", "asset_id"),
        Index("ix_asset_authorizations_project_id", "project_id"),
    )


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(2048))
    description: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(50)), default=list, server_default=text("'{}'")
    )
    criticality: Mapped[str] = mapped_column(
        String(16), default="medium", server_default=text("'medium'")
    )
    exposure: Mapped[str] = mapped_column(
        String(16), default="external", server_default=text("'external'")
    )
    status: Mapped[str] = mapped_column(
        String(16), default="active", server_default=text("'active'")
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    authorizations: Mapped[list[AssetAuthorization]] = relationship(
        lazy="selectin",
        order_by=AssetAuthorization.created_at.desc(),
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("project_id", "type", "value"),
        CheckConstraint(_in("type", ASSET_TYPES), name="type"),
        CheckConstraint(_in("criticality", CRITICALITIES), name="criticality"),
        CheckConstraint(_in("exposure", EXPOSURES), name="exposure"),
        CheckConstraint(_in("status", ASSET_STATUSES), name="status"),
        Index("ix_assets_project_id_status", "project_id", "status"),
    )
