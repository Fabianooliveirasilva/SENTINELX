"""Dependency providers for infrastructure and services (overridable in tests)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.context import RequestMeta
from app.core.security.passwords import PasswordService
from app.core.security.tokens import AccessTokenService
from app.services.ai import AIDispatcher, AIService
from app.services.assets import AssetService
from app.services.auth import AuthService
from app.services.email import EmailSender
from app.services.findings import FindingService
from app.services.intel import IntelService
from app.services.monitoring import MonitoringService
from app.services.projects import ProjectService
from app.services.rate_limit import RateLimiter
from app.services.reports import ReportDispatcher, ReportService
from app.services.scan_dispatch import IntelDispatcher, ScanDispatcher
from app.services.scans import ScanService
from app.services.schedules import ScheduleService
from app.services.users import UserService
from sentinelx_security.scope import ScopeEngine

_MAX_USER_AGENT = 256


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """One session per request. Services commit explicitly; anything left
    uncommitted (e.g. after an exception) is rolled back when the session closes."""
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with factory() as session:
        yield session


def get_request_meta(request: Request) -> RequestMeta:
    user_agent = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)
    return RequestMeta(
        ip_address=request.client.host if request.client else None,
        user_agent=user_agent[:_MAX_USER_AGENT] if user_agent else None,
        request_id=request_id if isinstance(request_id, str) else None,
    )


def get_rate_limiter(request: Request) -> RateLimiter:
    return RateLimiter(request.app.state.redis)


def get_password_service(request: Request) -> PasswordService:
    service: PasswordService = request.app.state.password_service
    return service


def get_email_sender(request: Request) -> EmailSender:
    sender: EmailSender = request.app.state.email_sender
    return sender


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
RequestMetaDep = Annotated[RequestMeta, Depends(get_request_meta)]
RateLimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
PasswordServiceDep = Annotated[PasswordService, Depends(get_password_service)]
EmailSenderDep = Annotated[EmailSender, Depends(get_email_sender)]


def get_auth_service(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    passwords: PasswordServiceDep,
    email_sender: EmailSenderDep,
) -> AuthService:
    access_tokens: AccessTokenService = request.app.state.access_token_service
    return AuthService(session, settings, passwords, access_tokens, email_sender)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


def get_user_service(
    session: SessionDep, passwords: PasswordServiceDep, auth: AuthServiceDep
) -> UserService:
    return UserService(session, passwords, auth)


def get_project_service(session: SessionDep) -> ProjectService:
    return ProjectService(session)


UserServiceDep = Annotated[UserService, Depends(get_user_service)]
ProjectServiceDep = Annotated[ProjectService, Depends(get_project_service)]


def get_scope_engine(request: Request) -> ScopeEngine:
    engine: ScopeEngine = request.app.state.scope_engine
    return engine


ScopeEngineDep = Annotated[ScopeEngine, Depends(get_scope_engine)]


def get_asset_service(
    session: SessionDep, engine: ScopeEngineDep, settings: SettingsDep
) -> AssetService:
    return AssetService(session, engine, settings)


AssetServiceDep = Annotated[AssetService, Depends(get_asset_service)]


def get_scan_dispatcher(request: Request) -> ScanDispatcher:
    dispatcher: ScanDispatcher = request.app.state.scan_dispatcher
    return dispatcher


def get_scan_service(
    session: SessionDep,
    engine: ScopeEngineDep,
    settings: SettingsDep,
    dispatcher: Annotated[ScanDispatcher, Depends(get_scan_dispatcher)],
) -> ScanService:
    return ScanService(session, engine, settings, dispatcher)


ScanServiceDep = Annotated[ScanService, Depends(get_scan_service)]


def get_finding_service(session: SessionDep) -> FindingService:
    return FindingService(session)


FindingServiceDep = Annotated[FindingService, Depends(get_finding_service)]


def get_intel_service(session: SessionDep) -> IntelService:
    return IntelService(session)


def get_intel_dispatcher(request: Request) -> IntelDispatcher:
    dispatcher: IntelDispatcher = request.app.state.intel_dispatcher
    return dispatcher


IntelServiceDep = Annotated[IntelService, Depends(get_intel_service)]
IntelDispatcherDep = Annotated[IntelDispatcher, Depends(get_intel_dispatcher)]


def get_monitoring_service(session: SessionDep, settings: SettingsDep) -> MonitoringService:
    return MonitoringService(session, settings)


def get_schedule_service(session: SessionDep) -> ScheduleService:
    return ScheduleService(session)


MonitoringServiceDep = Annotated[MonitoringService, Depends(get_monitoring_service)]
ScheduleServiceDep = Annotated[ScheduleService, Depends(get_schedule_service)]


def get_ai_dispatcher(request: Request) -> AIDispatcher:
    dispatcher: AIDispatcher = request.app.state.ai_dispatcher
    return dispatcher


def get_ai_service(
    session: SessionDep,
    settings: SettingsDep,
    dispatcher: Annotated[AIDispatcher, Depends(get_ai_dispatcher)],
) -> AIService:
    return AIService(session, settings, dispatcher)


AIServiceDep = Annotated[AIService, Depends(get_ai_service)]


def get_report_dispatcher(request: Request) -> ReportDispatcher:
    dispatcher: ReportDispatcher = request.app.state.report_dispatcher
    return dispatcher


def get_report_service(
    session: SessionDep,
    dispatcher: Annotated[ReportDispatcher, Depends(get_report_dispatcher)],
) -> ReportService:
    return ReportService(session, dispatcher)


ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]
