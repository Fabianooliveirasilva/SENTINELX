"""Dependency providers for health checks (overridable in tests)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from app.services.health import HealthService


def get_health_service(request: Request) -> HealthService:
    service = request.app.state.health_service
    if not isinstance(service, HealthService):  # pragma: no cover - wiring error
        raise TypeError("health_service is not configured on application state")
    return service


HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]
