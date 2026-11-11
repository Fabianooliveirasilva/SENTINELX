"""Access tokens (JWT) and opaque secret tokens.

* Access tokens are short-lived HS256 JWTs carrying only the subject, a token
  version and standard claims. Authorization data (role, permissions) is always
  loaded from the database, never trusted from the token.
* Refresh and password-reset tokens are opaque random strings; only their
  SHA-256 digest is stored, so a database leak does not yield usable tokens.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

import jwt

from app.core.config import Settings

ALGORITHM: Final = "HS256"
ISSUER: Final = "sentinelx"
AUDIENCE: Final = "sentinelx-api"
ACCESS_TOKEN_TYPE: Final = "access"  # noqa: S105 - JWT "typ" claim value
_OPAQUE_TOKEN_BYTES: Final = 32


class InvalidTokenError(Exception):
    """Raised for any malformed, expired or otherwise unacceptable token."""


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    user_id: uuid.UUID
    token_version: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    token: str
    expires_in: int


class AccessTokenService:
    def __init__(self, settings: Settings) -> None:
        self._key = settings.secret_key.get_secret_value()
        self._ttl = settings.access_token_ttl_seconds

    def issue(self, user_id: uuid.UUID, token_version: int) -> IssuedAccessToken:
        now = datetime.now(UTC)
        payload = {
            "sub": str(user_id),
            "ver": token_version,
            "typ": ACCESS_TOKEN_TYPE,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(seconds=self._ttl),
            "jti": uuid.uuid4().hex,
        }
        return IssuedAccessToken(
            token=jwt.encode(payload, self._key, algorithm=ALGORITHM), expires_in=self._ttl
        )

    def decode(self, token: str) -> AccessTokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._key,
                algorithms=[ALGORITHM],  # never accept "none" or asymmetric confusion
                audience=AUDIENCE,
                issuer=ISSUER,
                options={"require": ["sub", "exp", "iat", "nbf", "iss", "aud", "typ", "ver"]},
                leeway=5,
            )
            if payload["typ"] != ACCESS_TOKEN_TYPE:
                raise InvalidTokenError("unexpected token type")
            version = payload["ver"]
            if not isinstance(version, int) or isinstance(version, bool):
                raise InvalidTokenError("invalid token version")
            return AccessTokenClaims(
                user_id=uuid.UUID(str(payload["sub"])),
                token_version=version,
                expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
            )
        except (jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
            raise InvalidTokenError(str(exc)) from exc


def generate_opaque_token() -> str:
    return secrets.token_urlsafe(_OPAQUE_TOKEN_BYTES)


def hash_opaque_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(expected: str, provided: str) -> bool:
    return secrets.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))
