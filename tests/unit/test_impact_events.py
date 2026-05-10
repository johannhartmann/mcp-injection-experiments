"""Tests for the ImpactEvent contract.

ImpactEvent is what the demo emits when an exploit *actually* moves data,
files or state inside the demo zone (or when the defended mode blocks such a
move). Schema must be stable enough for the UI and JSONL ledger.
"""

from __future__ import annotations

import json

import pytest

from mcp_demo.shared.impact import ImpactEvent, ImpactValidationError


VALID_PAYLOAD: dict = {
    "experiment": "remote-direct-poisoning",
    "mode": "vulnerable",
    "impact_type": "mock_exfiltration",
    "actor": "poisoned-tool-description",
    "target": "mock-sink.attacker",
    "policy_decision": "allowed_by_vulnerable_mode",
    "canary_id": "CANARY_remote_direct_poisoning_demo",
    "artifact": "var/mock-inbox.jsonl:12",
    "user_visible_summary": "The canary appeared in the attacker inbox.",
}


def test_impact_event_requires_core_fields() -> None:
    event = ImpactEvent.model_validate(VALID_PAYLOAD)

    assert event.experiment == "remote-direct-poisoning"
    assert event.mode == "vulnerable"
    assert event.impact_type == "mock_exfiltration"
    assert event.actor == "poisoned-tool-description"
    assert event.target == "mock-sink.attacker"
    assert event.policy_decision == "allowed_by_vulnerable_mode"


@pytest.mark.parametrize(
    "missing_field",
    ["experiment", "mode", "impact_type", "actor", "target", "policy_decision"],
)
def test_missing_required_field_is_rejected(missing_field: str) -> None:
    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != missing_field}

    with pytest.raises(ImpactValidationError):
        ImpactEvent.model_validate(payload)


@pytest.mark.parametrize(
    "impact_type",
    [
        "mock_exfiltration",
        "mock_message_sent",
        "sandbox_file_written",
        "session_leak_visible",
        "permission_change_applied",
        "budget_consumed",
        "blocked_attempt_recorded",
    ],
)
def test_known_impact_types_are_accepted(impact_type: str) -> None:
    payload = {**VALID_PAYLOAD, "impact_type": impact_type}
    event = ImpactEvent.model_validate(payload)
    assert event.impact_type == impact_type


def test_unknown_impact_type_is_rejected() -> None:
    payload = {**VALID_PAYLOAD, "impact_type": "destroy_planet"}

    with pytest.raises(ImpactValidationError):
        ImpactEvent.model_validate(payload)


def test_impact_event_has_event_id_and_timestamp() -> None:
    event = ImpactEvent.model_validate(VALID_PAYLOAD)

    assert event.event_id.startswith("evt_")
    assert event.ts is not None


def test_impact_event_serialises_to_json() -> None:
    event = ImpactEvent.model_validate(VALID_PAYLOAD)
    raw = event.model_dump_json()
    payload = json.loads(raw)

    assert payload["experiment"] == "remote-direct-poisoning"
    assert payload["impact_type"] == "mock_exfiltration"
    assert payload["event_id"].startswith("evt_")


def test_blocked_event_marks_defended_mode() -> None:
    payload = {
        **VALID_PAYLOAD,
        "mode": "defended",
        "impact_type": "blocked_attempt_recorded",
        "policy_decision": "blocked",
        "actor": "policy.canary_exfiltration_policy",
    }
    event = ImpactEvent.model_validate(payload)
    assert event.policy_decision == "blocked"
    assert event.impact_type == "blocked_attempt_recorded"
