"""Authentication and authorization dependencies.

Every protected endpoint declares the permission it needs through
``require_permission``; authorization is decided here, server-side, from the
permissions loaded from the database for the authenticated user.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.context import Principal
from app.core.errors import AuthenticationError, PermissionDeniedError
from app.core.logging import get_logger
from app.core.permissions import Permission
from app.dependencies.core import AuthServiceDep

logger = get_logger(__name__)

_bearer = HTTPBearer(auto_error=False, description="JWT access token")


async def get_current_principal(
    auth: AuthServiceDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationError
    return await auth.authenticate(credentials.credentials)


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]


def require_permission(*permissions: Permission) -> Callable[[Principal], Awaitable[Principal]]:
    """Dependency factory: the principal must hold *all* listed permissions."""

    async def dependency(principal: CurrentPrincipal) -> Principal:
        missing = [p for p in permissions if not principal.has(p)]
        if missing:
            logger.warning(
                "permission_denied",
                user_id=str(principal.user_id),
                missing=[p.value for p in missing],
            )
            raise PermissionDeniedError
        return principal

    return dependency
