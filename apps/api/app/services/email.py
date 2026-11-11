"""Outbound email abstraction.

Phase 2 ships two backends:

* ``console`` (development only) prints messages to stderr so a developer can
  follow password-reset links locally. It deliberately bypasses the structured
  log pipeline so reset links never reach log storage. Forbidden in production.
* ``disabled`` drops messages (logging only the event, never the content).

SMTP/provider backends plug in behind the same protocol in a later phase.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Protocol

from app.core.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class EmailMessage:
    to: str
    subject: str
    body: str


class EmailSender(Protocol):
    async def send(self, message: EmailMessage) -> None: ...


class ConsoleEmailSender:
    async def send(self, message: EmailMessage) -> None:
        print(
            f"\n=== [DEV EMAIL] to={message.to} subject={message.subject!r} ===\n"
            f"{message.body}\n=== [END DEV EMAIL] ===\n",
            file=sys.stderr,
            flush=True,
        )


class DisabledEmailSender:
    async def send(self, message: EmailMessage) -> None:
        logger.warning("email_not_sent_backend_disabled", subject=message.subject)


def build_email_sender(settings: Settings) -> EmailSender:
    if settings.email_backend == "console":
        return ConsoleEmailSender()
    return DisabledEmailSender()
