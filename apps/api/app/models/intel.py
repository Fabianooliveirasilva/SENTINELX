"""Threat intelligence: CVEs (NVD), CPE match ranges, KEV, sync state, inventory."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin, utcnow


class CveMatch(UUIDPrimaryKeyMixin, Base):
    """One *vulnerable* CPE criterion of a CVE, with its version bounds."""

    __tablename__ = "cve_matches"

    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"))
    criteria: Mapped[str] = mapped_column(String(500))
    vendor: Mapped[str] = mapped_column(String(200))
    product: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(100))
    update: Mapped[str] = mapped_column(String(100))
    start_including: Mapped[str | None] = mapped_column(String(64))
    start_excluding: Mapped[str | None] = mapped_column(String(64))
    end_including: Mapped[str | None] = mapped_column(String(64))
    end_excluding: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_cve_matches_vendor_product", "vendor", "product"),
        Index("ix_cve_matches_cve_id", "cve_id"),
    )


class Cve(Base):
    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), default="nvd", server_default=text("'nvd'"))
    description: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    status: Mapped[str] = mapped_column(String(32), default="", server_default=text("''"))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_severity: Mapped[str | None] = mapped_column(String(16))
    cvss31_vector: Mapped[str | None] = mapped_column(String(200))
    cvss31_score: Mapped[float | None] = mapped_column(Float)
    cvss40_vector: Mapped[str | None] = mapped_column(String(200))
    cvss40_score: Mapped[float | None] = mapped_column(Float)
    cwes: Mapped[list[str]] = mapped_column(
        ARRAY(String(20)), default=list, server_default=text("'{}'")
    )
    references: Mapped[list[str]] = mapped_column(
        ARRAY(String(500)), default=list, server_default=text("'{}'")
    )
    kev_added_on: Mapped[date | None] = mapped_column(Date)
    kev_due_on: Mapped[date | None] = mapped_column(Date)
    kev_ransomware: Mapped[str | None] = mapped_column(String(20))
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )

    matches: Mapped[list[CveMatch]] = relationship(lazy="raise", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_cves_cvss_severity", "cvss_severity"),
        Index("ix_cves_kev_added_on", "kev_added_on"),
        Index("ix_cves_last_modified_at", "last_modified_at"),
    )


class ProductSync(Base):
    """Per-product NVD sync state (product-driven sync: only what we have seen)."""

    __tablename__ = "intel_product_syncs"

    vendor: Mapped[str] = mapped_column(String(200), primary_key=True)
    product: Mapped[str] = mapped_column(String(200), primary_key=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(
        String(16), default="pending", server_default=text("'pending'")
    )
    cve_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    error: Mapped[str | None] = mapped_column(String(300))


class IntelSource(Base):
    """Sync state of a whole feed (e.g. the CISA KEV catalog)."""

    __tablename__ = "intel_sources"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="never", server_default=text("'never'"))
    version: Mapped[str | None] = mapped_column(String(64))
    records: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    error: Mapped[str | None] = mapped_column(String(300))


class SoftwareComponent(UUIDPrimaryKeyMixin, Base):
    """Software observed on an asset (name + version + where), from the latest scans."""

    __tablename__ = "software_components"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(100))
    version: Mapped[str] = mapped_column(String(64), default="", server_default=text("''"))
    update: Mapped[str] = mapped_column(String(32), default="", server_default=text("''"))
    raw_version: Mapped[str] = mapped_column(String(64), default="", server_default=text("''"))
    cpes: Mapped[list[str]] = mapped_column(
        ARRAY(String(200)), default=list, server_default=text("'{}'")
    )
    location: Mapped[str] = mapped_column(String(300))
    correlatable: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    last_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("asset_id", "source", "name", "raw_version", "location"),
        Index("ix_software_components_project_id", "project_id"),
    )
