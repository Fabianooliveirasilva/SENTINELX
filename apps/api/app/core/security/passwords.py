"""Password hashing with Argon2id.

Hashing is CPU and memory intensive by design, so it runs in a worker thread to
avoid blocking the event loop. Verification of unknown accounts still performs a
full hash comparison against a dummy hash to keep response timing uniform.
"""

from __future__ import annotations

from dataclasses import dataclass

import anyio
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings

MIN_PASSWORD_LENGTH = 12
# Upper bound prevents denial of service through extremely long inputs.
MAX_PASSWORD_LENGTH = 128


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    needs_rehash: bool = False


class PasswordService:
    def __init__(self, settings: Settings) -> None:
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._dummy_hash = self._hasher.hash("sentinelx-timing-equalizer")

    async def hash(self, password: str) -> str:
        return await anyio.to_thread.run_sync(self._hasher.hash, password)

    async def verify(self, password_hash: str | None, password: str) -> VerificationResult:
        """Verify a password. ``password_hash=None`` verifies against a dummy hash."""
        target = password_hash or self._dummy_hash
        try:
            await anyio.to_thread.run_sync(self._hasher.verify, target, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return VerificationResult(valid=False)
        if password_hash is None:
            return VerificationResult(valid=False)
        return VerificationResult(
            valid=True, needs_rehash=self._hasher.check_needs_rehash(password_hash)
        )


def validate_password_strength(password: str, *, email: str | None = None) -> str:
    """NIST SP 800-63B style policy: length-based, no composition rules."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters long.")
    if not password.strip():
        raise ValueError("Password must not be blank.")
    if email and password.lower() in {email.lower(), email.split("@", 1)[0].lower()}:
        raise ValueError("Password must not match the email address.")
    return password
