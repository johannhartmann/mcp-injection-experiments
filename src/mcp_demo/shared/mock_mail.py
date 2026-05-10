"""In-memory mock-mail server.

Mock-mail is the trusted target the shadowing demo tries to subvert. It
keeps every "sent" message in process memory, persists each delivery to
``var/mock-inbox.jsonl`` for the audit trail and refuses any recipient
outside the RFC-2606 reserved ``.example`` TLD - including any attacker
shorthand the historical PoCs used.

The server never opens a socket, never imports ``smtplib`` lazily, never
calls out. Tests assert this with a ``smtplib`` monkeypatch.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

from mcp_demo.shared.mock_inbox import MockInbox


class MockMailRecipientError(ValueError):
    """Raised when a recipient is outside the .example TLD."""


_EXAMPLE_RE = re.compile(r"^[^@\s]+@([\w-]+\.)*example$", re.IGNORECASE)


def _validate_recipients(recipients: Iterable[str]) -> None:
    for rec in recipients:
        if not isinstance(rec, str) or not _EXAMPLE_RE.match(rec):
            raise MockMailRecipientError(
                f"recipient must be inside the reserved .example TLD: {rec!r}"
            )


class MockMailServer:
    """In-memory mock SMTP-equivalent. No outbound I/O of any kind."""

    def __init__(self, *, inbox: MockInbox | None = None) -> None:
        self._outbox: list[dict[str, Any]] = []
        self._inbox = inbox

    def send_email(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        actor: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        experiment: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        cc = list(cc or [])
        bcc = list(bcc or [])
        _validate_recipients([to, *cc, *bcc])

        record = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "actor": actor,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "body": body,
            "experiment": experiment,
            "session_id": session_id,
        }
        self._outbox.append(record)

        if self._inbox is not None and experiment is not None and session_id is not None:
            self._inbox.append(
                actor=actor,
                recipient=to,
                body=body,
                experiment=experiment,
                session_id=session_id,
                metadata={
                    "subject": subject,
                    "cc": cc,
                    "bcc": bcc,
                },
            )

        return record

    def outbox(self) -> list[dict[str, Any]]:
        return list(self._outbox)

    def reset(self) -> None:
        self._outbox.clear()
