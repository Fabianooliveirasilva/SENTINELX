"""Risk model configuration and project risk posture."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import ProjectServiceDep, RequestMetaDep, SessionDep
from app.schemas.common import error_responses
from app.schemas.findings import FindingRead
from app.schemas.risk import (
    PostureRead,
    ProjectRiskRead,
    RiskModelRead,
    RiskWeightsResult,
    RiskWeightsUpdate,
    TrendPoint,
)
from app.services.risk import load_weights, project_posture, save_weights, top_risks, trend
from sentinelx_security.risk import BANDS, MODEL_VERSION, WEIGHT_BOUNDS, RiskWeights

router = APIRouter(tags=["risk"])

_ERRORS = error_responses(401, 403, 404, 422)
CanRead = Annotated[Principal, Depends(require_permission(Permission.FINDINGS_READ))]
CanManage = Annotated[Principal, Depends(require_permission(Permission.SETTINGS_MANAGE))]

FORMULA = (
    "base = CVSS x 10 (or a severity default); "
    "adjusted = base x confidence x asset criticality x asset exposure; "
    "score = clamp(adjusted + KEV points + EPSS x EPSS points + age points, 0, 100). "
    "Project posture = worst + (100 - worst) x 0.5 x mean(next 4 worst) / 100."
)


def _model(weights: RiskWeights) -> RiskModelRead:
    return RiskModelRead(
        model_version=MODEL_VERSION,
        weights=weights.to_dict(),
        defaults=RiskWeights().to_dict(),
        bounds={k: dict(v) for k, v in WEIGHT_BOUNDS.items()},
        bands=dict(BANDS),
        formula=FORMULA,
    )


@router.get("/risk/model", responses=_ERRORS, summary="Risk model version, formula and weights")
async def risk_model(_principal: CanRead, session: SessionDep) -> RiskModelRead:
    return _model(await load_weights(session))


@router.put("/risk/weights", responses=_ERRORS, summary="Update weights and rescore (admins)")
async def update_weights(
    payload: RiskWeightsUpdate, principal: CanManage, session: SessionDep, meta: RequestMetaDep
) -> RiskWeightsResult:
    weights, changed = await save_weights(session, principal, payload.weights, meta)
    return RiskWeightsResult(**_model(weights).model_dump(), rescored=changed)


@router.post("/risk/weights/reset", responses=_ERRORS, summary="Restore default weights (admins)")
async def reset_weights(
    principal: CanManage, session: SessionDep, meta: RequestMetaDep
) -> RiskWeightsResult:
    weights, changed = await save_weights(session, principal, None, meta)
    return RiskWeightsResult(**_model(weights).model_dump(), rescored=changed)


@router.get("/projects/{project_id}/risk", responses=_ERRORS, summary="Project risk posture")
async def project_risk(
    project_id: uuid.UUID,
    principal: CanRead,
    projects: ProjectServiceDep,
    session: SessionDep,
) -> ProjectRiskRead:
    await projects.get(principal, project_id)
    current = await project_posture(session, project_id)
    return ProjectRiskRead(
        model_version=MODEL_VERSION,
        posture=PostureRead.model_validate(current),
        top_risks=[FindingRead.model_validate(f) for f in await top_risks(session, project_id)],
        trend=[TrendPoint.model_validate(t) for t in await trend(session, project_id)],
    )
