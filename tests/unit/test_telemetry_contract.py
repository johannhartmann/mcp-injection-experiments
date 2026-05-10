"""Tests for the unified TelemetryEvent contract."""

from __future__ import annotations

import pytest

from mcp_demo.shared.telemetry import (
    TelemetryEvent,
    TelemetryValidationError,
    scrub_payload,
)


VALID_PAYLOAD: dict = {
    "session_id": "sess-a",
    "experiment": "remote-direct-poisoning",
    "mode": "vulnerable",
    "event_type": "policy_decision",
    "severity": "warning",
    "message": "canary detected in tool argument",
    "data": {"policy": "canary_exfiltration_policy", "allowed": False},
}


def test_telemetry_event_has_event_id_and_ts() -> None:
    event = TelemetryEvent.model_validate(VALID_PAYLOAD)
    assert event.event_id.startswith("evt_")
    assert event.ts


def test_event_ids_are_unique() -> None:
    seen: set[str] = set()
    for _ in range(50):
        event = TelemetryEvent.model_validate(VALID_PAYLOAD)
        assert event.event_id not in seen
        seen.add(event.event_id)


def test_severity_is_constrained() -> None:
    payload = {**VALID_PAYLOAD, "severity": "armageddon"}
    with pytest.raises(TelemetryValidationError):
        TelemetryEvent.model_validate(payload)


@pytest.mark.parametrize(
    "raw",
    [
        "Bearer ABCDEF1234567890ABCDEF1234567890",
        "token=ghp_AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPp",
        "api_key=sk-proj-aaaaaaaaaaaaaaaaaaaaa",
    ],
)
def test_scrub_payload_redacts_token_patterns(raw: str) -> None:
    scrubbed = scrub_payload(raw)
    assert "ABCDEF1234567890" not in scrubbed
    assert "ghp_AaBb" not in scrubbed
    assert "sk-proj-aaa" not in scrubbed


def test_scrub_payload_keeps_canary_marker_visible() -> None:
    raw = "leak: CANARY_remote_direct_poisoning_abcdef1234567890"
    scrubbed = scrub_payload(raw)
    assert "CANARY_remote_direct_poisoning_abcdef1234567890" in scrubbed


def test_telemetry_event_serialises_to_json() -> None:
    event = TelemetryEvent.model_validate(VALID_PAYLOAD)
    raw = event.model_dump_json()
    assert event.event_id in raw
    assert "policy_decision" in raw
