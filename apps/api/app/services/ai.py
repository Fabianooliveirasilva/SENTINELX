"""AI analyst service.

API side: authorize, build the minimized context, reuse an identical recent
result, enforce the project's daily token budget, then queue the analysis for the
``ai`` worker — or answer immediately with a deterministic analysis when AI is
disabled, over budget or the queue is unavailable.

Worker side: rebuild the context, call the provider, validate the output against
the context, restore pseudonymized values, and record tokens and cost. Any
provider failure yields the deterministic analysis with a recorded reason.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from celery import Celery
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.context import AnalysisContext, build_context
from app.ai.fallback import FALLBACK_REASONS, deterministic
from app.ai.prompts import SYSTEM_PROMPT, TASKS, user_prompt
from app.ai.providers import AIProvider, ProviderUnavailableError
from app.ai.schemas import AnalysisOutput
from app.ai.validation import Validator, restore
from app.core.config import Settings
from app.core.context import Principal, RequestMeta
from app.core.errors import ConflictError, InvalidRequestError, NotFoundError
from app.core.logging import get_logger
from app.models import AIAnalysis
from app.schemas.pagination import PageParams
from app.services.audit import record_audit
from app.services.projects import ProjectService

logger = get_logger(__name__)

AI_TASK: Final = "sentinelx.ai.analyze"
AI_QUEUE: Final = "ai"
STALE_AFTER: Final = timedelta(minutes=15)
SUBJECTS: Final = {
    "finding_analysis": "finding",
    "scan_summary": "scan_job",
    "scan_comparison": "scan_job",
    "executive_summary": "project",
    "technical_summary": "project",
}
# Rough input estimate used for the budget check before the call (chars per token).
CHARS_PER_TOKEN: Final = 3


def utcnow() -> datetime:
    return datetime.now(UTC)


class AIDispatcher(Protocol):
    def dispatch(self, analysis_id: str) -> None: ...


class CeleryAIDispatcher:
    def __init__(self, app: Celery) -> None:
        self._app = app

    def dispatch(self, analysis_id: str) -> None:
        self._app.send_task(AI_TASK, args=[analysis_id], queue=AI_QUEUE, retry=False)


def _cost(settings: Settings, input_tokens: int, output_tokens: int) -> float:
    return round(
        input_tokens / 1e6 * settings.ai_input_price_per_mtok
        + output_tokens / 1e6 * settings.ai_output_price_per_mtok,
        6,
    )


def _complete_deterministic(
    analysis: AIAnalysis, context: AnalysisContext, reason: str, error: str | None = None
) -> None:
    output = restore(deterministic(context, reason), context)
    analysis.status = "completed"
    analysis.provider = "deterministic"
    analysis.model = None
    analysis.output = output.model_dump()
    analysis.fallback_reason = reason
    analysis.error = error
    analysis.completed_at = utcnow()


async def tokens_used_today(session: AsyncSession, project_id: uuid.UUID) -> tuple[int, float]:
    start = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    row = (
        await session.execute(
            select(
                func.coalesce(func.sum(AIAnalysis.input_tokens + AIAnalysis.output_tokens), 0),
                func.coalesce(func.sum(AIAnalysis.cost_usd), 0.0),
            ).where(AIAnalysis.project_id == project_id, AIAnalysis.created_at >= start)
        )
    ).one()
    return int(row[0]), float(row[1])


@dataclass(frozen=True, slots=True)
class AIUsage:
    enabled: bool
    model: str | None
    tokens_today: int
    cost_today_usd: float
    daily_token_budget: int


class AIService:
    def __init__(self, session: AsyncSession, settings: Settings, dispatcher: AIDispatcher) -> None:
        self._session = session
        self._settings = settings
        self._dispatcher = dispatcher
        self._projects = ProjectService(session)

    @property
    def enabled(self) -> bool:
        return self._settings.ai_provider != "disabled"

    # ------------------------------------------------------------------ queries

    async def _expire(self) -> None:
        """Analyses whose worker never reported back are failed, not left pending."""
        result = await self._session.execute(
            update(AIAnalysis)
            .where(
                AIAnalysis.status.in_(("pending", "running")),
                AIAnalysis.created_at < utcnow() - STALE_AFTER,
            )
            .values(
                status="failed",
                error="The analysis did not complete in time.",
                completed_at=utcnow(),
            )
            .returning(AIAnalysis.id)
        )
        if result.all():
            await self._session.commit()

    async def list(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        params: PageParams,
        *,
        subject_id: uuid.UUID | None = None,
        kind: str | None = None,
    ) -> tuple[Sequence[AIAnalysis], int]:
        await self._projects.get(principal, project_id)
        await self._expire()
        stmt = select(AIAnalysis).where(AIAnalysis.project_id == project_id)
        if subject_id:
            stmt = stmt.where(AIAnalysis.subject_id == subject_id)
        if kind:
            stmt = stmt.where(AIAnalysis.kind == kind)
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(AIAnalysis.created_at.desc())
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def get(
        self, principal: Principal, project_id: uuid.UUID, analysis_id: uuid.UUID
    ) -> AIAnalysis:
        await self._projects.get(principal, project_id)
        await self._expire()
        analysis = (
            await self._session.execute(
                select(AIAnalysis)
                .where(AIAnalysis.id == analysis_id, AIAnalysis.project_id == project_id)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if analysis is None:
            raise NotFoundError("Analysis not found.")
        return analysis

    async def usage(self, principal: Principal, project_id: uuid.UUID) -> AIUsage:
        await self._projects.get(principal, project_id)
        tokens, cost = await tokens_used_today(self._session, project_id)
        return AIUsage(
            enabled=self.enabled,
            model=self._settings.ai_model if self.enabled else None,
            tokens_today=tokens,
            cost_today_usd=round(cost, 4),
            daily_token_budget=self._settings.ai_daily_token_budget_per_project,
        )

    # ------------------------------------------------------------------ commands

    async def request(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        *,
        kind: str,
        subject_id: uuid.UUID | None,
        compare_with: uuid.UUID | None,
        refresh: bool,
        meta: RequestMeta,
    ) -> AIAnalysis:
        await self._projects.get(principal, project_id)
        task = TASKS.get(kind)
        if task is None:
            raise InvalidRequestError(f"Unknown analysis kind {kind!r}.")
        subject_type = SUBJECTS[kind]
        if subject_type == "project":
            subject_id = project_id
        elif subject_id is None:
            raise InvalidRequestError(f"A {subject_type.replace('_', ' ')} is required.")
        parameters: dict[str, Any] = {}
        if kind == "scan_comparison":
            if compare_with is None:
                raise InvalidRequestError("Choose a second scan to compare with.")
            parameters["compare_with"] = str(compare_with)
        context = await build_context(
            self._session,
            kind=kind,
            project_id=project_id,
            subject_id=subject_id,
            parameters=parameters,
        )
        model = self._settings.ai_model if self.enabled else "deterministic"
        input_hash = context.digest(task.full_version, model)

        if not refresh and self._settings.ai_result_reuse_hours:
            reusable = (
                await self._session.execute(
                    select(AIAnalysis)
                    .where(
                        AIAnalysis.project_id == project_id,
                        AIAnalysis.input_hash == input_hash,
                        AIAnalysis.status.in_(("pending", "running", "completed")),
                        AIAnalysis.created_at
                        >= utcnow() - timedelta(hours=self._settings.ai_result_reuse_hours),
                    )
                    .order_by(AIAnalysis.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            # A deterministic result is not reused once a model could do better.
            if reusable is not None and not (self.enabled and reusable.provider == "deterministic"):
                return reusable

        analysis = AIAnalysis(
            project_id=project_id,
            kind=kind,
            subject_type=subject_type,
            subject_id=subject_id,
            parameters=parameters,
            status="pending",
            prompt_version=task.full_version,
            input_hash=input_hash,
            context_summary=context.summary(),
            requested_by_id=principal.user_id,
            correlation_id=meta.request_id,
        )
        self._session.add(analysis)
        await self._session.flush()
        record_audit(
            self._session,
            action="ai.analysis_requested",
            actor=principal.actor,
            meta=meta,
            target_type="ai_analysis",
            target_id=analysis.id,
            project_id=project_id,
            details={
                "kind": kind,
                "subject_type": subject_type,
                "subject_id": str(subject_id),
                "prompt_version": task.full_version,
                "items": context.summary()["items"],
            },
        )

        reason: str | None = None
        if not self.enabled:
            reason = "ai_disabled"
        else:
            used, _ = await tokens_used_today(self._session, project_id)
            estimate = (
                len(SYSTEM_PROMPT + user_prompt(task, context.rendered())) // CHARS_PER_TOKEN
                + self._settings.ai_max_output_tokens
            )
            if used + estimate > self._settings.ai_daily_token_budget_per_project:
                reason = "budget_exceeded"
        if reason is not None:
            _complete_deterministic(analysis, context, reason)
            await self._session.commit()
            return analysis

        await self._session.commit()
        try:
            self._dispatcher.dispatch(str(analysis.id))
        except Exception as exc:  # noqa: BLE001 - any broker failure degrades gracefully
            logger.error(
                "ai_dispatch_failed", analysis_id=str(analysis.id), error=type(exc).__name__
            )
            _complete_deterministic(analysis, context, "queue_unavailable")
            await self._session.commit()
        return analysis

    async def review(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        analysis_id: uuid.UUID,
        meta: RequestMeta,
    ) -> AIAnalysis:
        analysis = await self.get(principal, project_id, analysis_id)
        if analysis.status != "completed":
            raise ConflictError("Only completed analyses can be reviewed.")
        if analysis.reviewed_at is not None:
            raise ConflictError("This analysis has already been reviewed.")
        analysis.reviewed_by_id = principal.user_id
        analysis.reviewed_by_email = principal.email
        analysis.reviewed_at = utcnow()
        record_audit(
            self._session,
            action="ai.analysis_reviewed",
            actor=principal.actor,
            meta=meta,
            target_type="ai_analysis",
            target_id=analysis.id,
            project_id=project_id,
            details={"kind": analysis.kind, "provider": analysis.provider},
        )
        await self._session.commit()
        return analysis


# --------------------------------------------------------------------- worker side


async def run_analysis(
    session: AsyncSession,
    analysis_id: uuid.UUID,
    settings: Settings,
    provider: AIProvider | None,
    *,
    unavailable_reason: str = "ai_not_configured",
) -> str | None:
    """Execute a queued analysis. Returns the final status, or None if skipped."""
    analysis = (
        await session.execute(
            select(AIAnalysis).where(AIAnalysis.id == analysis_id).with_for_update()
        )
    ).scalar_one_or_none()
    if analysis is None or analysis.status != "pending":
        return None
    analysis.status = "running"
    await session.commit()

    started = time.monotonic()
    try:
        context = await build_context(
            session,
            kind=analysis.kind,
            project_id=analysis.project_id,
            subject_id=analysis.subject_id,
            parameters=analysis.parameters,
        )
    except (NotFoundError, InvalidRequestError) as exc:
        analysis.status = "failed"
        analysis.error = exc.message[:300]
        analysis.completed_at = utcnow()
        await session.commit()
        return analysis.status

    task = TASKS[analysis.kind]
    if provider is None:
        _complete_deterministic(analysis, context, unavailable_reason)
    else:
        try:
            result = await provider.analyze(
                system=SYSTEM_PROMPT, user=user_prompt(task, context.rendered())
            )
        except ProviderUnavailableError as exc:
            _complete_deterministic(
                analysis, context, exc.reason, FALLBACK_REASONS.get(exc.reason, exc.detail)
            )
            logger.warning("ai_fallback", analysis_id=str(analysis.id), reason=exc.reason)
        else:
            validator = Validator(context)
            output: AnalysisOutput = restore(validator.output(result.output), context)
            analysis.status = "completed"
            analysis.provider = provider.name
            analysis.model = result.model
            analysis.output = output.model_dump()
            analysis.warnings = validator.warnings
            analysis.input_tokens = result.input_tokens
            analysis.output_tokens = result.output_tokens
            analysis.cost_usd = _cost(settings, result.input_tokens, result.output_tokens)
            analysis.completed_at = utcnow()
    analysis.duration_ms = int((time.monotonic() - started) * 1000)
    await session.commit()
    logger.info(
        "ai_analysis_completed",
        analysis_id=str(analysis.id),
        kind=analysis.kind,
        provider=analysis.provider,
        fallback_reason=analysis.fallback_reason,
        # Not "*_tokens": the log redactor masks keys containing "token".
        usage_input=analysis.input_tokens,
        usage_output=analysis.output_tokens,
        cost_usd=analysis.cost_usd,
        warnings=len(analysis.warnings),
    )
    return analysis.status
