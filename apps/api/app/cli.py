"""Administrative command line.

Bootstrap the first administrator (no self-registration is needed)::

    sentinelx-admin create-admin --email admin@example.com --full-name "Platform Admin"

The password is read interactively, or from SENTINELX_BOOTSTRAP_ADMIN_PASSWORD
for non-interactive environments (CI, provisioning). It is never accepted as a
command-line argument, which would expose it in shell history and process lists.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from pydantic import EmailStr, TypeAdapter, ValidationError

from app.core.config import get_settings
from app.core.context import ANONYMOUS, RequestMeta
from app.core.permissions import RoleName
from app.core.security.passwords import PasswordService, validate_password_strength
from app.db.session import create_engine, create_session_factory
from app.models import User
from app.repositories.users import UserRepository, normalize_email
from app.services.audit import record_audit

BOOTSTRAP_ENV_VAR = "SENTINELX_BOOTSTRAP_ADMIN_PASSWORD"
_EMAIL = TypeAdapter(EmailStr)
_CLI_META = RequestMeta(ip_address=None, user_agent="sentinelx-admin-cli", request_id=None)


def _validate_email(email: str) -> str:
    """Apply the same rules as the API so the account can actually sign in."""
    try:
        return normalize_email(_EMAIL.validate_python(email))
    except ValidationError as exc:
        raise SystemExit(f"Invalid email address: {email!r}") from exc


def _read_password(email: str) -> str:
    password = os.environ.get(BOOTSTRAP_ENV_VAR)
    if password is None:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat password: "):
            raise SystemExit("Passwords do not match.")
    try:
        return validate_password_strength(password, email=email)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


async def create_admin(email: str, full_name: str, password: str) -> bool:
    """Create an administrator. Returns False (no-op) if the email already exists."""
    settings = get_settings()
    engine = create_engine(settings)
    try:
        async with create_session_factory(engine)() as session:
            users = UserRepository(session)
            if await users.get_by_email(email) is not None:
                return False
            user = User(
                email=normalize_email(email),
                full_name=full_name,
                password_hash=await PasswordService(settings).hash(password),
                role_id=(await users.get_role(RoleName.ADMIN)).id,
            )
            session.add(user)
            await session.flush()
            record_audit(
                session,
                action="user.created",
                actor=ANONYMOUS,
                meta=_CLI_META,
                target_type="user",
                target_id=user.id,
                details={"role": RoleName.ADMIN.value, "source": "cli"},
            )
            await session.commit()
            return True
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelx-admin", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin", help="Create an administrator account")
    create.add_argument("--email", required=True)
    create.add_argument("--full-name", default="Administrator")
    args = parser.parse_args(argv)

    if args.command == "create-admin":
        email = _validate_email(args.email)
        password = _read_password(email)
        created = asyncio.run(create_admin(email, args.full_name.strip(), password))
        print(
            f"Administrator {email} created." if created else f"{email} already exists; unchanged."
        )
        return 0
    return 2  # pragma: no cover - argparse enforces a command


if __name__ == "__main__":
    sys.exit(main())
