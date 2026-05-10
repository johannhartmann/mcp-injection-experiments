"""Partitioned event queue used by the SSE/event timeline.

Each partition is keyed by ``(user_id, session_id)``. Event ids are unique
per partition *and* across partitions, so a resumable SSE Last-Event-Id
from session A can never address state in session B.
"""

from __future__ import annotations

import secrets
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque


class QueuePartitionError(KeyError):
    """Raised when consume is called with an unknown (user, session) pair."""


@dataclass
class _Partition:
    events: Deque[dict[str, Any]] = field(default_factory=deque)


class EventQueue:
    def __init__(self) -> None:
        self._partitions: dict[tuple[str, str], _Partition] = {}
        self._used_ids: set[str] = set()

    def _new_event_id(self) -> str:
        while True:
            candidate = secrets.token_urlsafe(12)
            if candidate not in self._used_ids:
                self._used_ids.add(candidate)
                return candidate

    def publish(
        self, *, user_id: str, session_id: str, event: dict[str, Any]
    ) -> dict[str, Any]:
        record = dict(event)
        record["event_id"] = self._new_event_id()
        record["_partition"] = (user_id, session_id)
        partition = self._partitions.setdefault(
            (user_id, session_id), _Partition()
        )
        partition.events.append(record)
        return record

    def consume(
        self, *, user_id: str, session_id: str
    ) -> list[dict[str, Any]]:
        partition = self._partitions.get((user_id, session_id))
        if partition is None:
            raise QueuePartitionError((user_id, session_id))
        events = list(partition.events)
        partition.events.clear()
        # strip the internal partition tag before handing events out
        return [{k: v for k, v in e.items() if k != "_partition"} for e in events]
