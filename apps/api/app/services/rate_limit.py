"""Fixed-window rate limiting backed by Redis.

Keys are hashed so identifiers such as email addresses are not stored in Redis
in clear text. If Redis is unavailable the limiter fails *open* and logs a
warning: availability of authentication is preferred, and brute force remains
bounded by the database-backed account lockout.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.errors import RateLimitedError
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter:
    def __init__(self, redis: Redis, *, prefix: str = "sentinelx:rl") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, scope: str, identifier: str) -> str:
        digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:32]
        return f"{self._prefix}:{scope}:{digest}"

    async def hit(
        self, scope: str, identifier: str, *, limit: int, window_seconds: int
    ) -> RateLimitResult:
        key = self._key(scope, identifier)
        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.set(key, 0, ex=window_seconds, nx=True)
                pipe.incr(key)
                pipe.ttl(key)
                _, count, ttl = await pipe.execute()
        except (RedisError, OSError) as exc:
            logger.warning("rate_limiter_unavailable", scope=scope, exc_type=type(exc).__name__)
            return RateLimitResult(allowed=True, remaining=limit, retry_after_seconds=0)

        count = int(count)
        retry_after = int(ttl) if int(ttl) > 0 else window_seconds
        return RateLimitResult(
            allowed=count <= limit,
            remaining=max(0, limit - count),
            retry_after_seconds=retry_after,
        )

    async def enforce(
        self, scope: str, identifier: str, *, limit: int, window_seconds: int
    ) -> None:
        result = await self.hit(scope, identifier, limit=limit, window_seconds=window_seconds)
        if not result.allowed:
            logger.warning("rate_limit_exceeded", scope=scope)
            raise RateLimitedError(result.retry_after_seconds)
