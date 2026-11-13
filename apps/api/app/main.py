"""FastAPI application factory.

Run with::

    uvicorn app.main:create_app --factory
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.security.passwords import PasswordService
from app.core.security.tokens import AccessTokenService
from app.db.session import create_engine, create_session_factory
from app.middleware.request_context import REQUEST_ID_HEADER, RequestContextMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.services.ai import CeleryAIDispatcher
from app.services.email import build_email_sender
from app.services.health import DatabaseHealthCheck, HealthService, RedisHealthCheck
from app.services.scan_dispatch import (
    CeleryIntelDispatcher,
    CeleryScanDispatcher,
    create_producer,
)
from sentinelx_security.scope import DnsResolver, NetworkPolicy, ScopeEngine, parse_lab_networks

logger = get_logger(__name__)


def _build_lifespan(
    settings: Settings,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine(settings)
        redis = Redis.from_url(
            settings.redis_url.get_secret_value(),
            socket_connect_timeout=settings.health_check_timeout_seconds,
            socket_timeout=settings.health_check_timeout_seconds,
            health_check_interval=30,
        )
        app.state.engine = engine
        app.state.session_factory = create_session_factory(engine)
        app.state.redis = redis
        app.state.health_service = HealthService(
            [DatabaseHealthCheck(engine), RedisHealthCheck(redis)],
            timeout_seconds=settings.health_check_timeout_seconds,
            version=settings.version,
        )
        logger.info("application_started", environment=settings.environment.value)
        try:
            yield
        finally:
            await redis.aclose()
            await engine.dispose()
            logger.info("application_stopped")

    return lifespan


def build_scope_engine(settings: Settings) -> ScopeEngine:
    return ScopeEngine(
        NetworkPolicy(parse_lab_networks(settings.scope_lab_networks)),
        DnsResolver(
            timeout_seconds=settings.dns_timeout_seconds, nameservers=settings.dns_nameservers
        ),
        lab_domains=settings.scope_lab_domains,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)

    app = FastAPI(
        title=f"{settings.app_name} API",
        version=settings.version,
        description="Attack Surface Management & AI-assisted security analysis platform.",
        lifespan=_build_lifespan(settings),
        docs_url="/api/docs" if settings.docs_enabled else None,
        redoc_url="/api/redoc" if settings.docs_enabled else None,
        openapi_url="/api/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings
    app.state.password_service = PasswordService(settings)
    app.state.access_token_service = AccessTokenService(settings)
    app.state.email_sender = build_email_sender(settings)
    app.state.scope_engine = build_scope_engine(settings)
    # Publishing is lazy: no broker connection is opened until a scan is requested.
    producer = create_producer(settings)
    app.state.scan_dispatcher = CeleryScanDispatcher(producer)
    app.state.intel_dispatcher = CeleryIntelDispatcher(producer)
    app.state.ai_dispatcher = CeleryAIDispatcher(producer)

    register_exception_handlers(app)

    # Middleware executes in reverse registration order: the last one added is the
    # outermost. Resulting order (outer -> inner):
    #   SecurityHeaders -> RequestContext -> TrustedHost -> CORS -> router
    # RequestContext converts unhandled exceptions to a 500 envelope, so it sits
    # inside SecurityHeaders: every response, including errors, is hardened and
    # carries the correlation ID.
    if settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
            expose_headers=[REQUEST_ID_HEADER],
            max_age=600,
        )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, enable_hsts=settings.is_production)

    app.include_router(api_router)
    return app
