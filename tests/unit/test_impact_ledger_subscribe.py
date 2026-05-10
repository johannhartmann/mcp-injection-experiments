"""ImpactLedger subscribe/unsubscribe/fan-out unit tests.

These tests are the actual contract behind ``GET /demo/events/stream``:
the SSE endpoint registers an asyncio.Queue on each ledger, and every
``record(event)`` call must put the event on every registered queue
without blocking and without crashing if a queue is full or has
already been removed.
"""

from __future__ import annotations

import asyncio

import pytest

from mcp_demo.shared.canary import issue_canary
from mcp_demo.shared.impact import (
    ImpactEvent,
    ImpactLedger,
    _new_event_id,
    _now_iso,
)


def _make_event(experiment: str = "remote-direct-poisoning") -> ImpactEvent:
    return ImpactEvent(
        event_id=_new_event_id(),
        ts=_now_iso(),
        experiment=experiment,
        mode="vulnerable",
        actor="test-actor",
        target="mock-sink",
        impact_type="blocked_attempt_recorded",
        canary_id=issue_canary(experiment_id=experiment).value,
        policy_decision="allowed_by_vulnerable_mode",
        session_id="unit-test",
    )


@pytest.mark.asyncio
async def test_subscribe_receives_recorded_event() -> None:
    ledger = ImpactLedger()
    q: asyncio.Queue[ImpactEvent] = asyncio.Queue()
    ledger.subscribe(q)

    evt = _make_event()
    ledger.record(evt)

    received = await asyncio.wait_for(q.get(), timeout=0.5)
    assert received.event_id == evt.event_id


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery() -> None:
    ledger = ImpactLedger()
    q: asyncio.Queue[ImpactEvent] = asyncio.Queue()
    ledger.subscribe(q)
    ledger.unsubscribe(q)

    ledger.record(_make_event())
    with pytest.raises(asyncio.QueueEmpty):
        q.get_nowait()


@pytest.mark.asyncio
async def test_unsubscribe_unknown_queue_is_silent() -> None:
    ledger = ImpactLedger()
    q: asyncio.Queue[ImpactEvent] = asyncio.Queue()
    # Must not raise even if we never subscribed.
    ledger.unsubscribe(q)


@pytest.mark.asyncio
async def test_full_queue_does_not_block_or_crash_record() -> None:
    ledger = ImpactLedger()
    q: asyncio.Queue[ImpactEvent] = asyncio.Queue(maxsize=1)
    ledger.subscribe(q)

    ledger.record(_make_event())  # fills the queue
    # Second record() should not raise even though the queue is full.
    ledger.record(_make_event())

    # The first event is still retrievable.
    first = await asyncio.wait_for(q.get(), timeout=0.5)
    assert first is not None


@pytest.mark.asyncio
async def test_multiple_subscribers_each_receive_event() -> None:
    ledger = ImpactLedger()
    queues = [asyncio.Queue[ImpactEvent]() for _ in range(3)]
    for q in queues:
        ledger.subscribe(q)

    evt = _make_event()
    ledger.record(evt)

    for q in queues:
        delivered = await asyncio.wait_for(q.get(), timeout=0.5)
        assert delivered.event_id == evt.event_id


@pytest.mark.asyncio
async def test_record_persists_to_jsonl_when_configured(tmp_path) -> None:
    path = tmp_path / "telemetry.jsonl"
    ledger = ImpactLedger(jsonl_path=path)
    evt = _make_event()
    ledger.record(evt)
    text = path.read_text(encoding="utf-8")
    assert evt.event_id in text
