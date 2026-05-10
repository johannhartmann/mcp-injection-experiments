"""Tests for the per-user/per-session state store.

Session-ID alone must not be a key for state lookup; the
(user_id, session_id) pair is the partition key.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from mcp_demo.shared.session_store import (
    PartitionedSessionStore,
    SessionExpired,
    SessionLookupError,
)


def test_state_is_partitioned_by_user_and_session() -> None:
    store = PartitionedSessionStore(ttl=timedelta(minutes=5))
    store.put(user_id="alice", session_id="s-1", key="canary", value="A")
    store.put(user_id="bob", session_id="s-1", key="canary", value="B")

    assert store.get(user_id="alice", session_id="s-1", key="canary") == "A"
    assert store.get(user_id="bob", session_id="s-1", key="canary") == "B"


def test_session_id_alone_does_not_grant_access_to_other_user_state() -> None:
    store = PartitionedSessionStore(ttl=timedelta(minutes=5))
    store.put(user_id="alice", session_id="s-1", key="canary", value="A")

    with pytest.raises(SessionLookupError):
        store.get(user_id="bob", session_id="s-1", key="canary")


def test_expired_sessions_are_evicted(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import datetime, timezone

    fake_now = [datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)]

    def now() -> "datetime":
        return fake_now[0]

    store = PartitionedSessionStore(ttl=timedelta(seconds=1), now_fn=now)
    store.put(user_id="alice", session_id="s-1", key="x", value=1)

    fake_now[0] = fake_now[0] + timedelta(seconds=2)
    with pytest.raises(SessionExpired):
        store.get(user_id="alice", session_id="s-1", key="x")


def test_unknown_session_raises_lookup_error() -> None:
    store = PartitionedSessionStore(ttl=timedelta(minutes=5))
    with pytest.raises(SessionLookupError):
        store.get(user_id="alice", session_id="missing", key="x")


def test_reset_session_removes_only_target_partition() -> None:
    store = PartitionedSessionStore(ttl=timedelta(minutes=5))
    store.put(user_id="alice", session_id="s-1", key="x", value=1)
    store.put(user_id="alice", session_id="s-2", key="x", value=2)
    store.put(user_id="bob", session_id="s-1", key="x", value=3)

    store.reset(user_id="alice", session_id="s-1")

    with pytest.raises(SessionLookupError):
        store.get(user_id="alice", session_id="s-1", key="x")
    assert store.get(user_id="alice", session_id="s-2", key="x") == 2
    assert store.get(user_id="bob", session_id="s-1", key="x") == 3
