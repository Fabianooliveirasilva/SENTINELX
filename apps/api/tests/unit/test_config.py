from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests.conftest import build_production_settings, build_settings


def test_defaults_are_valid() -> None:
    settings = build_settings()

    assert settings.docs_enabled is True
    assert settings.effective_celery_broker_url == "redis://127.0.0.1:1/0"


def test_secrets_are_not_rendered_in_repr() -> None:
    settings = build_settings(database_url="postgresql+asyncpg://u:topsecret@db/x")

    assert "topsecret" not in repr(settings)
    assert "topsecret" not in str(settings.model_dump())


def test_csv_values_are_parsed_from_strings() -> None:
    settings = build_settings(
        cors_allowed_origins="http://localhost:5173, https://app.example.com/",
        allowed_hosts="a.example, b.example",
    )

    assert settings.cors_allowed_origins == ["http://localhost:5173", "https://app.example.com"]
    assert settings.allowed_hosts == ["a.example", "b.example"]


@pytest.mark.parametrize(
    "origin", ["*", "localhost:5173", "ftp://example.com", "https://example.com/path"]
)
def test_rejects_unsafe_cors_origins(origin: str) -> None:
    with pytest.raises(ValidationError, match="CORS origin"):
        build_settings(cors_allowed_origins=[origin])


def test_rejects_wildcard_allowed_hosts() -> None:
    with pytest.raises(ValidationError, match="wildcard"):
        build_settings(allowed_hosts=["*"])


def test_rejects_non_async_database_driver() -> None:
    with pytest.raises(ValidationError, match="asyncpg"):
        build_settings(database_url="postgresql://u:p@db/x")


def test_rejects_non_redis_broker_url() -> None:
    with pytest.raises(ValidationError, match="redis"):
        build_settings(celery_broker_url="amqp://guest@rabbit//")


def test_rejects_short_secret_key() -> None:
    with pytest.raises(ValidationError):
        build_settings(secret_key="too-short")


def test_production_rejects_placeholder_secret() -> None:
    with pytest.raises(ValidationError, match="placeholder"):
        build_production_settings(secret_key="change-me-" + "x" * 40)


def test_production_disables_docs() -> None:
    settings = build_production_settings()

    assert settings.is_production
    assert settings.docs_enabled is False


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"cookie_secure": False}, "cookie_secure"),
        ({"email_backend": "console"}, "console"),
        ({"argon2_memory_cost_kib": 1024}, "Argon2id"),
    ],
)
def test_production_rejects_weak_auth_settings(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        build_production_settings(**overrides)


def test_frontend_base_url_must_be_absolute() -> None:
    with pytest.raises(ValidationError, match="frontend_base_url"):
        build_settings(frontend_base_url="/relative")
    assert build_settings(frontend_base_url="https://app.example.com/").frontend_base_url == (
        "https://app.example.com"
    )


def test_intel_settings_validation() -> None:
    from app.core.config import Settings

    base = {
        "secret_key": "x" * 40,
        "database_url": "postgresql+asyncpg://u:p@localhost/db",
        "redis_url": "redis://localhost:6379/0",
    }
    assert Settings(_env_file=None, nvd_api_key="  ", **base).nvd_api_key is None  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="https"):
        Settings(_env_file=None, nvd_base_url="http://nvd.example/", **base)  # type: ignore[arg-type]
