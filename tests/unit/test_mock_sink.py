"""Tests for the in-memory mock sink.

MockSink is the only place vulnerable demos are allowed to deliver
exfiltrated data. It records every drop, flags real canary leaks and scrubs
obvious token shapes so the demo logs do not become a leak surface
themselves.
"""

from __future__ import annotations

import pytest

from mcp_demo.shared.canary import issue_canary
from mcp_demo.shared.mock_sinks import MockSink, ScrubbingPolicy


def test_sink_records_drops_in_order() -> None:
    sink = MockSink()
    sink.deliver(actor="poisoned-tool", payload="hello")
    sink.deliver(actor="poisoned-tool", payload="world")

    events = sink.events()
    assert [e.payload for e in events] == ["hello", "world"]
    assert all(e.actor == "poisoned-tool" for e in events)


def test_sink_marks_canary_leak() -> None:
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    sink = MockSink()
    sink.register_canary(canary)

    sink.deliver(actor="poisoned-tool", payload=f"sidenote: {canary.value}")

    assert sink.secret_exfiltrated is True
    assert canary.value in sink.leaked_canary_values()


def test_sink_does_not_flag_when_no_canary_present() -> None:
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    sink = MockSink()
    sink.register_canary(canary)

    sink.deliver(actor="harmless-tool", payload="just a number: 42")

    assert sink.secret_exfiltrated is False
    assert sink.leaked_canary_values() == set()


@pytest.mark.parametrize(
    "raw, expected_marker",
    [
        ("Bearer abc123def456ghi789jkl012mno345", "Bearer [REDACTED]"),
        ("Authorization: Bearer abcdef1234567890ABCDEF1234567890", "Bearer [REDACTED]"),
        ("token=ghp_AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRr", "token=[REDACTED]"),
        ("api_key=sk-proj-abcdefABCDEF1234567890", "api_key=[REDACTED]"),
    ],
)
def test_sink_scrubs_obvious_token_patterns(raw: str, expected_marker: str) -> None:
    sink = MockSink(scrubbing=ScrubbingPolicy.default())
    sink.deliver(actor="leaky-agent", payload=raw)

    [event] = sink.events()
    assert expected_marker in event.payload
    # Original token body must not survive scrubbing.
    assert "abc123def456" not in event.payload
    assert "ghp_AaBbCc" not in event.payload
    assert "sk-proj-abcdef" not in event.payload


def test_sink_scrubbing_can_be_disabled_for_tests() -> None:
    sink = MockSink(scrubbing=ScrubbingPolicy.disabled())
    sink.deliver(actor="a", payload="Bearer raw-token-stays")

    [event] = sink.events()
    assert "raw-token-stays" in event.payload


def test_sink_reset_clears_state() -> None:
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    sink = MockSink()
    sink.register_canary(canary)
    sink.deliver(actor="x", payload=canary.value)

    assert sink.secret_exfiltrated is True
    sink.reset()

    assert sink.events() == []
    assert sink.secret_exfiltrated is False
    assert sink.leaked_canary_values() == set()
