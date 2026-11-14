"""TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) and recovery codes, standard library only.

SHA-1/6 digits/30 s is what every authenticator app supports; HMAC-SHA1 is not
weakened by SHA-1's collision weaknesses.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from typing import Final
from urllib.parse import quote

PERIOD: Final = 30
DIGITS: Final = 6
WINDOW: Final = 1  # accept the previous and next step to tolerate clock drift
SECRET_BYTES: Final = 20
RECOVERY_CODE_COUNT: Final = 10
_RECOVERY_ALPHABET: Final = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alikes


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _code(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def generate(secret: str, now: float) -> str:
    """The code an authenticator would show at ``now`` (used by tests and tooling)."""
    return _code(secret, current_step(now))


def current_step(now: float) -> int:
    return int(now // PERIOD)


def match_step(secret: str, code: str, now: float, *, after_step: int = -1) -> int | None:
    """Return the matched time step, or ``None``.

    Steps at or before ``after_step`` are rejected, so a code (or an older one) can
    never be used twice. Every candidate is compared in constant time.
    """
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isascii() or not code.isdigit():
        return None
    center = current_step(now)
    matched: int | None = None
    for step in range(center - WINDOW, center + WINDOW + 1):
        if hmac.compare_digest(_code(secret, step), code) and step > after_step:
            matched = step
    return matched


def provisioning_uri(issuer: str, account: str, secret: str) -> str:
    label = quote(f"{issuer}:{account}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )


def new_recovery_codes() -> list[str]:
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        return f"{raw[:5]}-{raw[5:]}"

    return [one() for _ in range(RECOVERY_CODE_COUNT)]


def normalize_recovery_code(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def hash_recovery_code(code: str) -> str:
    # 50 bits of entropy per code: a fast digest is adequate; the key is the entropy.
    return hashlib.sha256(normalize_recovery_code(code).encode()).hexdigest()
