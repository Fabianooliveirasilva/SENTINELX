"""Security audit trail.

Audit entries are added to the caller's session so they commit atomically with
the change they describe. For failed operations (where the business transaction
is rolled back) callers commit the audit entry explicitly before raising.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Actor, RequestMeta
from app.models import AuditLog

Outcome = Literal["success", "failure"]


def record_audit(
    session: AsyncSession,
    *,
    action: str,
    actor: Actor,
    meta: RequestMeta,
    outcome: Outcome = "success",
    target_type: str | None = None,
    target_id: uuid.UUID | str | None = None,
    project_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        outcome=outcome,
        actor_id=actor.id,
        actor_email=actor.email,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        project_id=project_id,
        ip_address=meta.ip_address,
        user_agent=meta.user_agent,
        request_id=meta.request_id,
        details=details or {},
    )
    session.add(entry)
    return entry
