"""Tests for the partitioned event queue used by the SSE/event timeline."""

from __future__ import annotations

import pytest

from mcp_demo.shared.event_queue import (
    EventQueue,
    QueuePartitionError,
)


@pytest.fixture
def queue() -> EventQueue:
    return EventQueue()


def test_events_published_to_a_are_not_returned_for_b(queue: EventQueue) -> None:
    queue.publish(user_id="alice", session_id="s-1", event={"text": "hello"})
    queue.publish(user_id="bob", session_id="s-1", event={"text": "hi-bob"})

    a = queue.consume(user_id="alice", session_id="s-1")
    b = queue.consume(user_id="bob", session_id="s-1")

    assert {e["text"] for e in a} == {"hello"}
    assert {e["text"] for e in b} == {"hi-bob"}


def test_event_ids_are_unique_within_partition(queue: EventQueue) -> None:
    for i in range(5):
        queue.publish(user_id="alice", session_id="s-1", event={"i": i})
    events = queue.consume(user_id="alice", session_id="s-1")
    ids = [e["event_id"] for e in events]
    assert len(set(ids)) == len(ids)


def test_event_ids_are_not_reused_across_partitions(queue: EventQueue) -> None:
    queue.publish(user_id="alice", session_id="s-1", event={"x": 1})
    queue.publish(user_id="bob", session_id="s-1", event={"x": 2})

    a_ids = [e["event_id"] for e in queue.consume(user_id="alice", session_id="s-1")]
    b_ids = [e["event_id"] for e in queue.consume(user_id="bob", session_id="s-1")]
    assert set(a_ids).isdisjoint(set(b_ids))


def test_consume_with_unknown_partition_raises(queue: EventQueue) -> None:
    with pytest.raises(QueuePartitionError):
        queue.consume(user_id="ghost", session_id="never")
