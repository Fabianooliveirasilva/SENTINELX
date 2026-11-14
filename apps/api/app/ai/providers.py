"""AI provider abstraction and the Anthropic implementation.

Providers receive a finished prompt and return validated structured output, or
raise :class:`ProviderUnavailableError` with a reason code; callers then fall back to
the deterministic analysis. No provider is ever given tools: the model can only
produce the schema-constrained text it is asked for.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol

import anthropic
from anthropic.types.beta import BetaOutputConfigParam
from pydantic import ValidationError

from app.ai.schemas import AnalysisOutput
from app.core.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)

FALLBACK_BETA: Final = "server-side-fallback-2026-07-01"


class ProviderUnavailableError(Exception):
    """The provider could not produce an analysis. ``reason`` is a safe code."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = (detail or reason)[:300]


@dataclass(frozen=True, slots=True)
class ProviderResult:
    output: AnalysisOutput
    model: str
    input_tokens: int
    output_tokens: int


class AIProvider(Protocol):
    name: str

    async def analyze(self, *, system: str, user: str) -> ProviderResult: ...


class AnthropicProvider:
    """Claude via the official SDK: structured outputs, refusal fallback, bounded."""

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        effort: Literal["low", "medium", "high"],
        max_output_tokens: int,
        timeout_seconds: float,
        http_client: Any = None,
    ) -> None:
        self._model = model
        self._output_config: BetaOutputConfigParam = {"effort": effort}
        self._max_tokens = max_output_tokens
        # One retry at most: the worker's time limit must cover timeout x attempts.
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key,
            timeout=timeout_seconds,
            max_retries=1,
            http_client=http_client,
        )

    @classmethod
    def from_settings(cls, settings: Settings, http_client: Any = None) -> AnthropicProvider:
        if settings.anthropic_api_key is None:
            raise ProviderUnavailableError("ai_not_configured")
        return cls(
            api_key=settings.anthropic_api_key.get_secret_value(),
            model=settings.ai_model,
            effort=settings.ai_effort,
            max_output_tokens=settings.ai_max_output_tokens,
            timeout_seconds=settings.ai_timeout_seconds,
            http_client=http_client,
        )

    async def analyze(self, *, system: str, user: str) -> ProviderResult:
        try:
            response = await self._client.beta.messages.parse(
                model=self._model,
                max_tokens=self._max_tokens,
                # The system prompt is identical across requests: cache it.
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": user}],
                output_format=AnalysisOutput,
                output_config=self._output_config,
                # A policy decline is retried server-side on a fallback model.
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
        except anthropic.APITimeoutError as exc:
            raise ProviderUnavailableError("timeout") from exc
        except anthropic.RateLimitError as exc:
            raise ProviderUnavailableError("rate_limited") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderUnavailableError("connection_error") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderUnavailableError("api_error", f"HTTP {exc.status_code}") from exc
        except ValidationError as exc:
            raise ProviderUnavailableError("invalid_output") from exc

        usage = response.usage
        input_tokens = (
            usage.input_tokens
            + (usage.cache_creation_input_tokens or 0)
            + (usage.cache_read_input_tokens or 0)
        )
        logger.info(
            "ai_provider_response",
            model=response.model,
            stop_reason=response.stop_reason,
            usage_input=input_tokens,
            usage_output=usage.output_tokens,
            request_id=getattr(response, "_request_id", None),
        )
        if response.stop_reason == "refusal":
            raise ProviderUnavailableError("refused")
        if response.stop_reason == "max_tokens":
            raise ProviderUnavailableError("truncated")
        output = response.parsed_output
        if not isinstance(output, AnalysisOutput):
            raise ProviderUnavailableError("invalid_output")
        return ProviderResult(
            output=output,
            model=response.model,
            input_tokens=input_tokens,
            output_tokens=usage.output_tokens,
        )
