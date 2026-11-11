"""Application configuration.

All runtime configuration is read from environment variables prefixed with
``SENTINELX_`` (optionally from a local ``.env`` file). Secrets are wrapped in
``SecretStr`` so they are never rendered by ``repr()`` or accidentally logged.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INSECURE_SECRET_MARKERS = ("change-me", "changeme", "insecure", "example")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    """Typed, validated application settings."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINELX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    environment: Environment = Environment.DEVELOPMENT
    app_name: str = "SentinelX"
    version: str = "0.1.0"

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    secret_key: SecretStr = Field(min_length=32)

    database_url: SecretStr
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=5, ge=0, le=50)
    db_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)

    redis_url: SecretStr
    celery_broker_url: SecretStr | None = None
    celery_result_backend: SecretStr | None = None

    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1"]
    )

    health_check_timeout_seconds: float = Field(default=2.0, gt=0, le=30)

    # ------------------------------------------------------------------ validators

    @field_validator("cors_allowed_origins", "allowed_hosts", mode="before")
    @classmethod
    def _parse_csv(cls, value: object) -> object:
        return _split_csv(value)

    @field_validator("cors_allowed_origins")
    @classmethod
    def _validate_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            parts = urlsplit(origin)
            if origin == "*" or parts.scheme not in {"http", "https"} or not parts.netloc:
                raise ValueError(
                    f"invalid CORS origin {origin!r}: must be an explicit http(s) origin"
                )
            if parts.path not in {"", "/"} or parts.query or parts.fragment:
                raise ValueError(f"invalid CORS origin {origin!r}: must not contain a path")
        return [origin.rstrip("/") for origin in origins]

    @field_validator("allowed_hosts")
    @classmethod
    def _validate_hosts(cls, hosts: list[str]) -> list[str]:
        if not hosts:
            raise ValueError("allowed_hosts must not be empty")
        if "*" in hosts:
            raise ValueError("wildcard '*' is not permitted in allowed_hosts")
        return hosts

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use the 'postgresql+asyncpg://' scheme")
        return value

    @field_validator("redis_url", "celery_broker_url", "celery_result_backend")
    @classmethod
    def _validate_redis_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and urlsplit(value.get_secret_value()).scheme not in {
            "redis",
            "rediss",
        }:
            raise ValueError("Redis URLs must use the 'redis://' or 'rediss://' scheme")
        return value

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> Settings:
        if self.environment is not Environment.PRODUCTION:
            return self
        secret = self.secret_key.get_secret_value().lower()
        if any(marker in secret for marker in _INSECURE_SECRET_MARKERS):
            raise ValueError("secret_key contains a placeholder value; generate a random secret")
        if not self.log_json:
            raise ValueError("log_json must be enabled in production")
        return self

    # ------------------------------------------------------------------ derived

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are disabled in production to reduce exposure."""
        return not self.is_production

    @property
    def effective_celery_broker_url(self) -> str:
        return (self.celery_broker_url or self.redis_url).get_secret_value()

    @property
    def effective_celery_result_backend(self) -> str:
        return (self.celery_result_backend or self.redis_url).get_secret_value()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance (validated once)."""
    return Settings()  # values are provided by the environment
