"""Append-only JSONL inbox used by mock-mail and mock-message demos.

Mock-mail/WhatsApp/Slack-style targets all share the same persistence shape:
each delivery is a single JSON object on its own line under
``var/mock-inbox.jsonl``. This is intentionally trivial; the goal is a
visible artefact, not a real messaging system.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class MockInbox:
    """Append-only JSONL message log."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def append(
        self,
        *,
        actor: str,
        recipient: str,
        body: str,
        experiment: str,
        session_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "experiment": experiment,
            "session_id": session_id,
            "actor": actor,
            "recipient": recipient,
            "body": body,
            "metadata": dict(metadata or {}),
        }
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False))
            fh.write("\n")
        return record

    def lines(self) -> list[str]:
        if not self._path.exists():
            return []
        return self._path.read_text(encoding="utf-8").splitlines()

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.lines()]
