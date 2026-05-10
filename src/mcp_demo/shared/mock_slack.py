"""In-memory mock Slack workspace + mock link unfurler.

Slack-style link unfurling turns a posted URL into an outbound preview
request. We model both sides locally: a ``MockSlack`` workspace with
public and private channels, and a ``MockUnfurler`` that records URL
fetch attempts as JSON-line entries instead of contacting the URL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


@dataclass
class MockSlack:
    private_channels: dict[str, list[str]] = field(default_factory=dict)
    public_channels: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    messages_path: Path = field(default_factory=Path)

    def set_private_message(self, *, channel: str, body: str) -> None:
        self.private_channels.setdefault(channel, []).append(body)

    def read_private_channel(self, channel: str) -> list[str]:
        return list(self.private_channels.get(channel, []))

    def post_message(
        self,
        *,
        channel: str,
        body: str,
        actor: str,
        unfurl_links: bool,
        session_id: str,
        experiment: str,
    ) -> dict[str, Any]:
        record = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "channel": channel,
            "body": body,
            "actor": actor,
            "unfurl_links": unfurl_links,
            "visibility": "public" if channel.startswith("public-") else "private",
            "session_id": session_id,
            "experiment": experiment,
        }
        self.public_channels.setdefault(channel, []).append(record)
        if self.messages_path != Path():
            self.messages_path.parent.mkdir(parents=True, exist_ok=True)
            with self.messages_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False))
                fh.write("\n")
        return record


@dataclass
class MockUnfurler:
    requests_path: Path

    def __post_init__(self) -> None:
        self.requests_path = Path(self.requests_path)
        self.requests_path.parent.mkdir(parents=True, exist_ok=True)

    def fetch_preview(
        self, *, url: str, on_behalf_of_channel: str, session_id: str, experiment: str
    ) -> dict[str, Any]:
        parsed = urlsplit(url)
        record = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "url": url,
            "host": parsed.hostname or "",
            "query": parsed.query,
            "on_behalf_of_channel": on_behalf_of_channel,
            "session_id": session_id,
            "experiment": experiment,
        }
        with self.requests_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False))
            fh.write("\n")
        return record

    def requests(self) -> list[dict[str, Any]]:
        if not self.requests_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.requests_path.read_text(encoding="utf-8").splitlines()
        ]
