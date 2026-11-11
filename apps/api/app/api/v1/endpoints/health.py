"""Health endpoints used by container orchestration and the frontend."""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from app.dependencies.health import HealthServiceDep
from app.schemas.common import ErrorResponse
from app.schemas.health import ComponentStatus, LivenessReport, ReadinessReport

router = APIRouter(prefix="/health", tags=["health"])


@router.get(
    "/live",
    summary="Liveness probe",
    description="Returns 200 while the API process is running. Does not touch dependencies.",
)
async def liveness() -> LivenessReport:
    return LivenessReport()


@router.get(
    "/ready",
    summary="Readiness probe",
    description=(
        "Checks PostgreSQL and Redis connectivity. Returns 200 when all dependencies are "
        "reachable, otherwise 503 with the per-component status."
    ),
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessReport},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
    },
)
async def readiness(response: Response, health: HealthServiceDep) -> ReadinessReport:
    report = await health.readiness()
    if report.status is not ComponentStatus.OK:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return report
