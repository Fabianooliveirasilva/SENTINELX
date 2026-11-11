"""Celery application for the scanner sandbox.

The sandbox consumes only the ``scans`` queue. It deliberately has **no**
database URL, secret key or other platform credentials: its configuration is
limited to the broker URL and scope/scanner tuning. Scope is re-evaluated here,
at execution time, with fresh DNS resolution and address pinning.

Start with::

    celery -A sentinelx_workers.scanner_app:scanner_app worker -Q scans
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any

from celery import Celery
from celery.signals import setup_logging
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.logging import configure_logging
from sentinelx_security.scanners import ScannerConfig
from sentinelx_security.scope import DnsResolver, NetworkPolicy, ScopeEngine, parse_lab_networks

SCANNER_QUEUE = "scans"


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class ScannerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELX_", extra="ignore", frozen=True)

    celery_broker_url: SecretStr | None = None
    redis_url: SecretStr | None = None
    log_level: str = "INFO"
    log_json: bool = True
    scope_lab_networks: Annotated[list[str], NoDecode] = Field(default_factory=list)
    scope_lab_domains: Annotated[list[str], NoDecode] = Field(default_factory=list)
    dns_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    dns_nameservers: Annotated[list[str], NoDecode] = Field(default_factory=list)
    nmap_binary: str = "nmap"
    crtsh_url: str = "https://crt.sh/"
    passive_sources_enabled: bool = True
    nuclei_binary: str = "nuclei"
    nuclei_templates_dir: str = "/opt/nuclei-templates"
    nuclei_version: str = "unknown"
    nuclei_templates_version: str = "unknown"
    zap_api_url: str = "http://zap:8080"
    zap_api_key: SecretStr = SecretStr("")
    zap_proxy_bind: str = "0.0.0.0"  # noqa: S104  # nosec B104 - internal ZAP network
    zap_proxy_port: int = Field(default=8899, ge=1, le=65535)
    zap_proxy_host: str = "scanner-zap"

    @field_validator("scope_lab_networks", "scope_lab_domains", "dns_nameservers", mode="before")
    @classmethod
    def _parse_csv(cls, value: object) -> object:
        return _split_csv(value)

    @property
    def broker_url(self) -> str:
        url = self.celery_broker_url or self.redis_url
        if url is None:
            raise ValueError("Set SENTINELX_CELERY_BROKER_URL for the scanner sandbox.")
        return url.get_secret_value()

    def scope_engine(self) -> ScopeEngine:
        return ScopeEngine(
            NetworkPolicy(parse_lab_networks(self.scope_lab_networks)),
            DnsResolver(
                timeout_seconds=self.dns_timeout_seconds,
                nameservers=self.dns_nameservers,
            ),
            lab_domains=self.scope_lab_domains,
        )

    def scanner_config(self) -> ScannerConfig:
        return ScannerConfig(
            nmap_binary=self.nmap_binary,
            dns_timeout_seconds=self.dns_timeout_seconds,
            dns_nameservers=tuple(self.dns_nameservers),
            crtsh_url=self.crtsh_url,
            passive_sources_enabled=self.passive_sources_enabled,
            nuclei_binary=self.nuclei_binary,
            nuclei_templates_dir=self.nuclei_templates_dir,
            nuclei_version=self.nuclei_version,
            nuclei_templates_version=self.nuclei_templates_version,
            zap_api_url=self.zap_api_url,
            zap_api_key=self.zap_api_key.get_secret_value(),
            zap_proxy_bind=self.zap_proxy_bind,
            zap_proxy_port=self.zap_proxy_port,
            zap_proxy_host=self.zap_proxy_host,
        )


@lru_cache
def get_scanner_settings() -> ScannerSettings:
    return ScannerSettings()  # populated from the environment


def create_scanner_app(broker_url: str) -> Celery:
    app = Celery(
        "sentinelx-scanner", broker=broker_url, include=["sentinelx_workers.tasks.scanner"]
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        result_accept_content=["json"],
        task_ignore_result=True,
        task_default_queue=SCANNER_QUEUE,
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        worker_hijack_root_logger=False,
        # Recycle the process after each scan: no state survives between targets.
        worker_max_tasks_per_child=1,
        broker_connection_retry_on_startup=True,
    )
    return app


@setup_logging.connect  # type: ignore[untyped-decorator]
def _configure_logging(**_kwargs: Any) -> None:
    settings = get_scanner_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)


scanner_app = create_scanner_app(get_scanner_settings().broker_url)
