"""Outbound email abstraction.

Phase 2 ships two backends:

* ``console`` (development only) prints messages to stderr so a developer can
  follow password-reset links locally. It deliberately bypasses the structured
  log pipeline so reset links never reach log storage. Forbidden in production.
* ``smtp`` (Phase 8) delivers through an SMTP relay with STARTTLS or implicit
  TLS and certificate verification; credentials are never logged.
* ``disabled`` drops messages (logging only the event, never the content).
"""

from __future__ import annotations

import asyncio
import smtplib
import ssl
import sys
from dataclasses import dataclass
from email.message import EmailMessage as MimeMessage
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


class SmtpEmailSender:
    def __init__(self, settings: Settings) -> None:
        if not settings.smtp_host:
            raise ValueError("smtp_host is required for the smtp backend")
        self._host = settings.smtp_host
        self._port = settings.smtp_port
        self._username = settings.smtp_username
        self._password = settings.smtp_password
        self._implicit_tls = settings.smtp_security == "tls"
        self._timeout = settings.smtp_timeout_seconds
        self._sender = settings.email_from

    async def send(self, message: EmailMessage) -> None:
        await asyncio.to_thread(self._send, message)

    def _send(self, message: EmailMessage) -> None:
        mime = MimeMessage()
        mime["From"] = self._sender
        mime["To"] = message.to
        mime["Subject"] = message.subject.replace("\r", " ").replace("\n", " ")
        mime.set_content(message.body)
        context = ssl.create_default_context()
        client: smtplib.SMTP
        if self._implicit_tls:
            client = smtplib.SMTP_SSL(
                self._host, self._port, timeout=self._timeout, context=context
            )
        else:
            client = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
        with client:
            if not self._implicit_tls:
                client.starttls(context=context)
            if self._username and self._password:
                client.login(self._username, self._password.get_secret_value())
            client.send_message(mime)


def build_email_sender(settings: Settings) -> EmailSender:
    if settings.email_backend == "console":
        return ConsoleEmailSender()
    if settings.email_backend == "smtp":
        return SmtpEmailSender(settings)
    return DisabledEmailSender()
