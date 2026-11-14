"""Authenticated symmetric encryption for secrets at rest (Fernet, HKDF per purpose)."""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecretDecryptionError(Exception):
    """The ciphertext is corrupt or ``SECRET_KEY`` changed."""


class PurposeSecretBox:
    def __init__(self, secret_key: str, purpose: str) -> None:
        key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=f"sentinelx/{purpose}/v1".encode()
        ).derive(secret_key.encode())
        self._fernet = Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise SecretDecryptionError from exc
