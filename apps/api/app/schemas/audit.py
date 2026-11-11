"""Audit log schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    action: str
    outcome: str
    actor_id: uuid.UUID | None
    actor_email: str | None
    target_type: str | None
    target_id: str | None
    project_id: uuid.UUID | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    details: dict[str, Any]
