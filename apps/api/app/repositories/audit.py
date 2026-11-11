"""Read access to the audit trail (writes go through ``record_audit``)."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog
from app.schemas.pagination import PageParams


@dataclass(frozen=True, slots=True)
class AuditFilters:
    action: str | None = None
    actor_id: uuid.UUID | None = None
    project_id: uuid.UUID | None = None
    outcome: str | None = None
    since: datetime | None = None
    until: datetime | None = None


class AuditLogRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list(
        self, params: PageParams, filters: AuditFilters
    ) -> tuple[Sequence[AuditLog], int]:
        conditions = []
        if filters.action:
            conditions.append(AuditLog.action == filters.action)
        if filters.actor_id:
            conditions.append(AuditLog.actor_id == filters.actor_id)
        if filters.project_id:
            conditions.append(AuditLog.project_id == filters.project_id)
        if filters.outcome:
            conditions.append(AuditLog.outcome == filters.outcome)
        if filters.since:
            conditions.append(AuditLog.created_at >= filters.since)
        if filters.until:
            conditions.append(AuditLog.created_at < filters.until)

        stmt = select(AuditLog).where(*conditions)
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def distinct_actions(self) -> Sequence[str]:
        stmt = select(AuditLog.action).distinct().order_by(AuditLog.action)
        return (await self._session.execute(stmt)).scalars().all()
