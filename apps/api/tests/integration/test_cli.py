"""Administrator bootstrap CLI."""

from __future__ import annotations

import pytest

from app import cli
from app.core.permissions import RoleName
from tests.integration.conftest import ApiStack

pytestmark = pytest.mark.integration


async def test_create_admin_is_idempotent_and_can_login(stack: ApiStack) -> None:
    assert await cli.create_admin("root@example.com", "Root", "bootstrap-passphrase-1") is True
    assert await cli.create_admin("ROOT@example.com", "Root", "other-passphrase-123") is False

    headers = await stack.login("root@example.com", "bootstrap-passphrase-1")
    me = (await stack.client.get("/api/v1/auth/me", headers=headers)).json()
    assert me["role"] == RoleName.ADMIN.value


def test_cli_rejects_weak_password_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(cli.BOOTSTRAP_ENV_VAR, "short")

    with pytest.raises(SystemExit, match="at least"):
        cli.main(["create-admin", "--email", "x@example.com"])


def test_cli_main_creates_admin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], stack: ApiStack
) -> None:
    monkeypatch.setenv(cli.BOOTSTRAP_ENV_VAR, "bootstrap-passphrase-2")

    assert cli.main(["create-admin", "--email", "ops@example.com", "--full-name", "Ops"]) == 0
    assert "Administrator ops@example.com created." in capsys.readouterr().out


@pytest.mark.parametrize("email", ["not-an-email", "admin@sentinelx.local"])
def test_cli_rejects_emails_the_api_would_refuse(email: str) -> None:
    with pytest.raises(SystemExit, match="Invalid email"):
        cli.main(["create-admin", "--email", email])
