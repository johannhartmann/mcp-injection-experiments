"""Per-user/per-session state store with TTL eviction.

State is keyed by ``(user_id, session_id, key)``. Looking up state with a
session id but the wrong user id raises :class:`SessionLookupError` -
session id alone is not an authentication token. Entries older than the
configured TTL are evicted lazily on access (no background thread).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable


class SessionLookupError(KeyError):
    """Raised when no state exists for the requested (user, session, key)."""


class SessionExpired(KeyError):
    """Raised when state existed but has aged past the configured TTL."""


@dataclass
class _Entry:
    value: Any
    written_at: datetime


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class PartitionedSessionStore:
    def __init__(
        self,
        *,
        ttl: timedelta,
        now_fn: Callable[[], datetime] = _default_now,
    ) -> None:
        self._ttl = ttl
        self._now = now_fn
        self._partitions: dict[tuple[str, str], dict[str, _Entry]] = {}

    def put(
        self, *, user_id: str, session_id: str, key: str, value: Any
    ) -> None:
        partition = self._partitions.setdefault((user_id, session_id), {})
        partition[key] = _Entry(value=value, written_at=self._now())

    def get(self, *, user_id: str, session_id: str, key: str) -> Any:
        partition = self._partitions.get((user_id, session_id))
        if partition is None or key not in partition:
            raise SessionLookupError((user_id, session_id, key))
        entry = partition[key]
        if self._now() - entry.written_at > self._ttl:
            # Lazy eviction.
            del partition[key]
            if not partition:
                self._partitions.pop((user_id, session_id), None)
            raise SessionExpired((user_id, session_id, key))
        return entry.value

    def reset(self, *, user_id: str, session_id: str) -> None:
        self._partitions.pop((user_id, session_id), None)

    def has(self, *, user_id: str, session_id: str) -> bool:
        return (user_id, session_id) in self._partitions
