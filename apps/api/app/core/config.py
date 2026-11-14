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

from sentinelx_security.scope.network_policy import parse_lab_networks
from sentinelx_security.scope.targets import TargetError, normalize_hostname, parse_ip

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

    # --- Authentication -------------------------------------------------------
    access_token_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=7 * 24 * 3600, ge=3600, le=30 * 24 * 3600)
    password_reset_ttl_seconds: int = Field(default=1800, ge=300, le=24 * 3600)
    # OWASP Password Storage Cheat Sheet minimum for Argon2id: m=19 MiB, t=2, p=1.
    argon2_time_cost: int = Field(default=2, ge=1, le=10)
    argon2_memory_cost_kib: int = Field(default=19456, ge=8, le=1_048_576)
    argon2_parallelism: int = Field(default=1, ge=1, le=8)
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_lockout_seconds: int = Field(default=900, ge=60, le=24 * 3600)
    allow_self_registration: bool = False
    # Browsers treat http://localhost as a secure context, so Secure cookies work in
    # local development too. Only disable for non-browser test clients.
    cookie_secure: bool = True
    frontend_base_url: str = "http://localhost:8080"
    email_backend: Literal["console", "smtp", "disabled"] = "console"
    email_from: str = "SentinelX <no-reply@sentinelx.example.com>"
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    # "starttls" upgrades a plain connection; "tls" is implicit TLS (port 465).
    smtp_security: Literal["starttls", "tls"] = "starttls"
    smtp_timeout_seconds: float = Field(default=15.0, gt=0, le=120)

    # --- Monitoring & notifications ---------------------------------------------
    webhook_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    notification_max_attempts: int = Field(default=6, ge=1, le=20)
    notification_batch_size: int = Field(default=50, ge=1, le=500)
    # Webhooks may target private addresses only inside these networks (e.g. an
    # internal chat server). Loopback, link-local and metadata stay blocked.
    webhook_allowed_networks: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- Scope enforcement ------------------------------------------------------
    # Private networks / internal domains of intentionally vulnerable labs that may
    # be registered and tested. Loopback, link-local and metadata stay blocked.
    scope_lab_networks: Annotated[list[str], NoDecode] = Field(default_factory=list)
    scope_lab_domains: Annotated[list[str], NoDecode] = Field(default_factory=list)
    dns_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    dns_nameservers: Annotated[list[str], NoDecode] = Field(default_factory=list)
    max_authorization_days: int = Field(default=366, ge=1, le=3660)

    # --- Scans ------------------------------------------------------------------
    max_concurrent_scans_per_project: int = Field(default=3, ge=1, le=50)
    max_daily_scans_per_project: int = Field(default=50, ge=1, le=10_000)
    scan_timeout_seconds: int = Field(default=240, ge=10, le=3000)
    # ZAP spiders and (optionally) attacks a whole application: it gets its own budget.
    zap_scan_timeout_seconds: int = Field(default=900, ge=60, le=7200)
    scan_queue_timeout_seconds: int = Field(default=1800, ge=60, le=24 * 3600)

    def scan_timeout_for(self, scanner: str) -> int:
        return self.zap_scan_timeout_seconds if scanner == "zap" else self.scan_timeout_seconds

    @property
    def max_scan_timeout_seconds(self) -> int:
        return max(self.scan_timeout_seconds, self.zap_scan_timeout_seconds)

    # --- Threat intelligence ------------------------------------------------------
    intel_enabled: bool = True
    nvd_api_key: SecretStr | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_url: str = "https://api.first.org/data/v1/epss"
    intel_product_ttl_hours: int = Field(default=24, ge=1, le=24 * 30)
    intel_max_products_per_run: int = Field(default=20, ge=1, le=500)

    # --- Rate limits (requests per window) --------------------------------------
    rate_limit_login_per_minute: int = Field(default=10, ge=1)
    rate_limit_refresh_per_minute: int = Field(default=60, ge=1)
    rate_limit_password_reset_per_hour: int = Field(default=5, ge=1)
    rate_limit_register_per_hour: int = Field(default=5, ge=1)
    rate_limit_scope_check_per_minute: int = Field(default=30, ge=1)

    # ------------------------------------------------------------------ validators

    @field_validator(
        "cors_allowed_origins",
        "allowed_hosts",
        "scope_lab_networks",
        "scope_lab_domains",
        "dns_nameservers",
        "webhook_allowed_networks",
        mode="before",
    )
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

    @field_validator("scope_lab_networks", "webhook_allowed_networks")
    @classmethod
    def _validate_lab_networks(cls, values: list[str]) -> list[str]:
        return [str(network) for network in parse_lab_networks(values)]

    @field_validator("scope_lab_domains")
    @classmethod
    def _validate_lab_domains(cls, values: list[str]) -> list[str]:
        try:
            return [normalize_hostname(v) for v in values]
        except TargetError as exc:
            raise ValueError(f"invalid lab domain: {exc.message}") from exc

    @field_validator("dns_nameservers")
    @classmethod
    def _validate_nameservers(cls, values: list[str]) -> list[str]:
        try:
            return [parse_ip(v).compressed for v in values]
        except TargetError as exc:
            raise ValueError("dns_nameservers must be IP addresses") from exc

    @field_validator("nvd_api_key", mode="before")
    @classmethod
    def _empty_key_is_none(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("nvd_base_url", "kev_url", "epss_url")
    @classmethod
    def _validate_intel_urls(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.netloc:
            raise ValueError("intelligence feed URLs must be absolute https URLs")
        return value

    @field_validator("frontend_base_url")
    @classmethod
    def _validate_frontend_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError("frontend_base_url must be an absolute http(s) URL")
        return value.rstrip("/")

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
        if not self.cookie_secure:
            raise ValueError("cookie_secure must be enabled in production")
        if self.email_backend == "console":
            raise ValueError("the console email backend is not permitted in production")
        if self.argon2_memory_cost_kib < 19456 or self.argon2_time_cost < 2:
            raise ValueError("Argon2id parameters are below the OWASP minimum for production")
        return self

    @model_validator(mode="after")
    def _require_smtp_host(self) -> Settings:
        if self.email_backend == "smtp" and not self.smtp_host:
            raise ValueError("smtp_host is required when email_backend is 'smtp'")
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
