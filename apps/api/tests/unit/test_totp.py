"""TOTP against the RFC 6238 reference vectors, plus replay and recovery-code handling."""

from __future__ import annotations

import base64

import pytest

from app.core.security import totp
from app.core.security.secretbox import PurposeSecretBox, SecretDecryptionError

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize(
    ("moment", "expected"),
    [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (2000000000, "279037")],
)
def test_rfc6238_reference_vectors(moment: int, expected: str) -> None:
    assert totp.generate(RFC_SECRET, moment) == expected


def test_match_window_and_replay_protection() -> None:
    now = 1_700_000_000.0
    code = totp.generate(RFC_SECRET, now)
    step = totp.match_step(RFC_SECRET, code, now)
    assert step == totp.current_step(now)
    assert step is not None
    assert totp.match_step(RFC_SECRET, code, now, after_step=step) is None  # replay
    # Previous and next steps are tolerated; two steps away is not.
    assert totp.match_step(RFC_SECRET, totp.generate(RFC_SECRET, now - 30), now) is not None
    assert totp.match_step(RFC_SECRET, totp.generate(RFC_SECRET, now + 30), now) is not None
    assert totp.match_step(RFC_SECRET, totp.generate(RFC_SECRET, now + 90), now) is None


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "١٢٣٤٥٦", "12 34 5"])
def test_malformed_codes_are_rejected(bad: str) -> None:
    assert totp.match_step(RFC_SECRET, bad, 59.0) is None


def test_provisioning_uri_escapes_the_label() -> None:
    uri = totp.provisioning_uri("Sentinel X", "a+b@example.com", "ABC")
    assert uri.startswith("otpauth://totp/Sentinel%20X%3Aa%2Bb%40example.com?secret=ABC")
    assert "issuer=Sentinel%20X" in uri


def test_recovery_codes_are_unique_and_normalized() -> None:
    codes = totp.new_recovery_codes()
    assert len(set(codes)) == totp.RECOVERY_CODE_COUNT
    assert totp.hash_recovery_code(codes[0]) == totp.hash_recovery_code(codes[0].upper())
    assert totp.hash_recovery_code(codes[0]) == totp.hash_recovery_code(codes[0].replace("-", " "))


def test_secretbox_round_trip_and_key_binding() -> None:
    box = PurposeSecretBox("k" * 40, "mfa-secrets")
    token = box.encrypt("JBSWY3DPEHPK3PXP")
    assert "JBSWY3DPEHPK3PXP" not in token
    assert box.decrypt(token) == "JBSWY3DPEHPK3PXP"
    with pytest.raises(SecretDecryptionError):
        PurposeSecretBox("x" * 40, "mfa-secrets").decrypt(token)
    with pytest.raises(SecretDecryptionError):
        PurposeSecretBox("k" * 40, "other-purpose").decrypt(token)
