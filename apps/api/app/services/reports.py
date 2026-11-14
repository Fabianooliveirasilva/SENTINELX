"""Report generation: requested by the API, rendered by the orchestrator worker."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol

from celery import Celery
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import undefer

from app.core.context import Principal, RequestMeta
from app.core.errors import ConflictError, InvalidRequestError, NotFoundError
from app.core.logging import get_logger
from app.models import Project, Report, ScanJob
from app.reports.builder import SCHEMA_VERSION, ReportRequest, build_report
from app.reports.pdf import render_pdf
from app.schemas.pagination import PageParams
from app.services.audit import record_audit
from app.services.projects import ProjectService

logger = get_logger(__name__)

REPORT_TASK: Final = "sentinelx.reports.generate"
REPORT_QUEUE: Final = "orchestrator"
MAX_REPORT_BYTES: Final = 25 * 1024 * 1024
STALE_AFTER: Final = timedelta(minutes=15)
MEDIA_TYPES: Final = {"pdf": "application/pdf", "json": "application/json"}


def utcnow() -> datetime:
    return datetime.now(UTC)


class ReportDispatcher(Protocol):
    def dispatch(self, report_id: str) -> None: ...


class CeleryReportDispatcher:
    def __init__(self, app: Celery) -> None:
        self._app = app

    def dispatch(self, report_id: str) -> None:
        self._app.send_task(REPORT_TASK, args=[report_id], queue=REPORT_QUEUE, retry=False)


def filename(report: Report) -> str:
    stamp = (report.completed_at or report.created_at).strftime("%Y%m%d-%H%M")
    return f"sentinelx-report-{report.scope}-{stamp}-{str(report.id)[:8]}.{report.format}"


class ReportService:
    def __init__(self, session: AsyncSession, dispatcher: ReportDispatcher) -> None:
        self._session = session
        self._dispatcher = dispatcher
        self._projects = ProjectService(session)

    async def _expire(self) -> None:
        result = await self._session.execute(
            update(Report)
            .where(
                Report.status.in_(("pending", "running")),
                Report.created_at < utcnow() - STALE_AFTER,
            )
            .values(status="failed", error="The report was not generated in time.")
            .returning(Report.id)
        )
        if result.all():
            await self._session.commit()

    async def list(
        self, principal: Principal, project_id: uuid.UUID, params: PageParams
    ) -> tuple[Sequence[Report], int]:
        await self._projects.get(principal, project_id)
        await self._expire()
        stmt = select(Report).where(Report.project_id == project_id)
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(Report.created_at.desc())
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def get(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        report_id: uuid.UUID,
        *,
        with_content: bool = False,
    ) -> Report:
        await self._projects.get(principal, project_id)
        await self._expire()
        stmt = (
            select(Report)
            .where(Report.id == report_id, Report.project_id == project_id)
            .execution_options(populate_existing=True)
        )
        if with_content:
            stmt = stmt.options(undefer(Report.content))
        report = (await self._session.execute(stmt)).scalar_one_or_none()
        if report is None:
            raise NotFoundError("Report not found.")
        return report

    async def request(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        *,
        scope: str,
        scan_job_id: uuid.UUID | None,
        fmt: str,
        title: str | None,
        include_resolved: bool,
        include_ai: bool,
        include_evidence: bool,
        meta: RequestMeta,
    ) -> Report:
        project: Project = await self._projects.get(principal, project_id)
        if scope == "scan":
            if scan_job_id is None:
                raise InvalidRequestError("A scan report needs a scan.")
            job = (
                await self._session.execute(
                    select(ScanJob).where(
                        ScanJob.id == scan_job_id, ScanJob.project_id == project_id
                    )
                )
            ).scalar_one_or_none()
            if job is None:
                raise NotFoundError("Scan not found.")
            if job.status not in ("completed", "failed"):
                raise InvalidRequestError("Only finished scans can be reported.")
            default_title = f"Scan report — {job.target}"
        else:
            scan_job_id = None
            default_title = f"Security assessment — {project.name}"
        report = Report(
            project_id=project_id,
            scope=scope,
            scan_job_id=scan_job_id,
            format=fmt,
            title=(title or default_title).strip()[:200],
            parameters={
                "include_resolved": include_resolved,
                "include_ai": include_ai,
                "include_evidence": include_evidence,
            },
            status="pending",
            schema_version=SCHEMA_VERSION,
            generated_by_id=principal.user_id,
            generated_by_email=principal.email,
            correlation_id=meta.request_id,
        )
        self._session.add(report)
        await self._session.flush()
        record_audit(
            self._session,
            action="report.requested",
            actor=principal.actor,
            meta=meta,
            target_type="report",
            target_id=report.id,
            project_id=project_id,
            details={"scope": scope, "format": fmt, **report.parameters},
        )
        await self._session.commit()
        try:
            self._dispatcher.dispatch(str(report.id))
        except Exception as exc:  # noqa: BLE001 - surfaced as a failed report
            logger.error(
                "report_dispatch_failed", report_id=str(report.id), error=type(exc).__name__
            )
            report.status = "failed"
            report.error = "The report queue is unavailable. Please try again later."
            await self._session.commit()
        return report

    async def download(
        self, principal: Principal, project_id: uuid.UUID, report_id: uuid.UUID, meta: RequestMeta
    ) -> Report:
        report = await self.get(principal, project_id, report_id, with_content=True)
        if report.status != "completed" or report.content is None:
            raise ConflictError("The report is not ready.")
        record_audit(
            self._session,
            action="report.downloaded",
            actor=principal.actor,
            meta=meta,
            target_type="report",
            target_id=report.id,
            project_id=project_id,
            details={"format": report.format, "sha256": report.sha256},
        )
        await self._session.commit()
        return report

    async def delete(
        self, principal: Principal, project_id: uuid.UUID, report_id: uuid.UUID, meta: RequestMeta
    ) -> None:
        report = await self.get(principal, project_id, report_id)
        record_audit(
            self._session,
            action="report.deleted",
            actor=principal.actor,
            meta=meta,
            target_type="report",
            target_id=report.id,
            project_id=project_id,
            details={"format": report.format, "sha256": report.sha256},
        )
        await self._session.delete(report)
        await self._session.commit()


# --------------------------------------------------------------------- worker side


def render(data: dict[str, Any], fmt: str) -> bytes:
    if fmt == "pdf":
        return render_pdf(data)
    return json.dumps(data, ensure_ascii=False, indent=2, default=str).encode()


async def generate_report(session: AsyncSession, report_id: uuid.UUID) -> str | None:
    report = (
        await session.execute(select(Report).where(Report.id == report_id).with_for_update())
    ).scalar_one_or_none()
    if report is None or report.status != "pending":
        return None
    report.status = "running"
    await session.commit()
    try:
        data = await build_report(
            session,
            ReportRequest(
                report_id=report.id,
                project_id=report.project_id,
                scope=report.scope,
                scan_job_id=report.scan_job_id,
                title=report.title,
                format=report.format,
                include_resolved=bool(report.parameters.get("include_resolved")),
                include_ai=bool(report.parameters.get("include_ai", True)),
                include_evidence=bool(report.parameters.get("include_evidence", True)),
                generated_by=report.generated_by_email,
            ),
        )
        content = render(data, report.format)
    except LookupError as exc:
        report.status = "failed"
        report.error = str(exc)[:300]
        await session.commit()
        return report.status
    except Exception as exc:
        logger.exception("report_generation_failed", report_id=str(report.id))
        report.status = "failed"
        report.error = f"Report generation failed ({type(exc).__name__})."
        await session.commit()
        return report.status
    if len(content) > MAX_REPORT_BYTES:
        report.status = "failed"
        report.error = "The report exceeds the maximum size; narrow its scope."
        await session.commit()
        return report.status
    report.content = content
    report.size_bytes = len(content)
    report.sha256 = hashlib.sha256(content).hexdigest()
    report.summary = {
        "findings": len(data["findings"]),
        "assets": len(data["scope"]["assets"]),
        "scans": len(data["scans"]),
        "ai_commentary": len(data["ai_commentary"]),
        "by_risk_band": data["severity_distribution"]["by_risk_band"],
    }
    report.status = "completed"
    report.completed_at = utcnow()
    await session.commit()
    logger.info(
        "report_generated",
        report_id=str(report.id),
        format=report.format,
        size_bytes=report.size_bytes,
        findings=report.summary["findings"],
    )
    return report.status
