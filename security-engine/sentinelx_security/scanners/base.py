"""Common scanner interface.

Every scanner implements the five-step contract:

* ``validate_scope`` — re-run the scope engine immediately before execution and
  return the decision (including the pinned addresses for active techniques).
* ``execute`` — perform the work against the pinned addresses only.
* ``normalize_results`` — convert raw tool output into typed observations.
* ``handle_errors`` — map any exception to a safe, user-presentable ScanError.
* ``record_evidence`` — keep bounded raw evidence for traceability.

Scanner output is untrusted data (it comes from systems we do not control). It
is size-limited, never executed or rendered as HTML, and observations only carry
plain JSON values.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Final

from sentinelx_security.scope import (
    AssetType,
    ScopeAsset,
    ScopeDecision,
    ScopeEngine,
    Target,
    Technique,
)
from sentinelx_security.scope.targets import IPAddress

MAX_EVIDENCE_CHARS: Final = 65_536
SCANNER_PACKAGE_VERSION: Final = "0.4.0"


class ScannerName(StrEnum):
    DNS = "dns"
    SUBDOMAINS = "subdomains"
    TLS = "tls"
    NMAP = "nmap"
    HTTP = "http"


class ScanError(Exception):
    """A failure that is safe to show to users (no internal details)."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


class UnsupportedTargetError(ScanError):
    def __init__(self, message: str) -> None:
        super().__init__("unsupported_target", message)


@dataclass(frozen=True, slots=True)
class Observation:
    """A normalized fact produced by a scanner (not yet a finding)."""

    kind: str
    key: str
    data: Mapping[str, Any]
    attention: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "key": self.key,
            "data": dict(self.data),
            "attention": list(self.attention),
        }


@dataclass(frozen=True, slots=True)
class Evidence:
    label: str
    content: str
    media_type: str = "text/plain"

    @classmethod
    def bounded(cls, label: str, content: str, media_type: str = "text/plain") -> Evidence:
        if len(content) > MAX_EVIDENCE_CHARS:
            content = content[:MAX_EVIDENCE_CHARS] + "\n…[truncated]"
        return cls(label=label, content=content, media_type=media_type)

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "content": self.content, "media_type": self.media_type}


@dataclass(frozen=True, slots=True)
class ScanContext:
    target: Target
    pinned_addresses: tuple[IPAddress, ...]
    profile: str
    timeout_seconds: float


@dataclass(slots=True)
class RawOutput:
    data: Any
    tool_versions: dict[str, str] = field(default_factory=dict)


class Scanner(ABC):
    name: ClassVar[ScannerName]
    technique: ClassVar[Technique]
    description: ClassVar[str]
    profiles: ClassVar[Mapping[str, str]] = {"default": "Default profile"}
    default_profile: ClassVar[str] = "default"
    supported_asset_types: ClassVar[frozenset[AssetType]]

    @classmethod
    def target_for(cls, asset_type: AssetType, value: str) -> str:
        """Default scan target derived from an asset."""
        if asset_type not in cls.supported_asset_types:
            raise UnsupportedTargetError(
                f"The {cls.name.value} scanner does not support {asset_type.value} assets."
            )
        return value

    async def validate_scope(
        self,
        engine: ScopeEngine,
        target: str,
        assets: Sequence[ScopeAsset],
        now: datetime,
    ) -> ScopeDecision:
        return await engine.evaluate(target, self.technique, assets, now)

    @abstractmethod
    async def execute(self, ctx: ScanContext) -> RawOutput: ...

    @abstractmethod
    def normalize_results(self, raw: RawOutput) -> list[Observation]: ...

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:  # noqa: ARG002 - optional hook
        return []

    def handle_errors(self, exc: BaseException) -> ScanError:
        if isinstance(exc, ScanError):
            return exc
        if isinstance(exc, TimeoutError | asyncio.TimeoutError):
            return ScanError("timeout", "The scan exceeded its time limit.", retryable=True)
        if isinstance(exc, ConnectionRefusedError):
            return ScanError("connection_refused", "The target refused the connection.")
        if isinstance(exc, OSError):
            return ScanError(
                "network_error", "A network error occurred while scanning.", retryable=True
            )
        return ScanError("scanner_error", "The scanner failed unexpectedly.")
