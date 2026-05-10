"""Tests for the demo run result contract.

The result is the contract the web/JSON-RPC layer hands back to clients and
to the UI. Field set is fixed by architecture/api-contracts.md.
"""

from __future__ import annotations

import json

import pytest

from mcp_demo.shared.results import DemoResult, DemoResultValidationError


REQUIRED_FIELDS = {
    "experiment",
    "mode",
    "violation_detected",
    "secret_exfiltrated",
    "blocked_by",
    "events",
}


def test_minimal_result_has_all_required_fields() -> None:
    result = DemoResult(
        experiment="remote-direct-poisoning",
        mode="vulnerable",
        violation_detected=True,
        secret_exfiltrated=True,
        blocked_by=[],
        events=[],
    )

    payload = result.model_dump()
    assert REQUIRED_FIELDS.issubset(payload.keys())


def test_result_serialises_to_stable_json() -> None:
    result = DemoResult(
        experiment="remote-direct-poisoning",
        mode="defended",
        violation_detected=True,
        secret_exfiltrated=False,
        blocked_by=["canary_exfiltration_policy"],
        events=[
            {
                "type": "policy_decision",
                "policy": "canary_exfiltration_policy",
                "allowed": False,
            }
        ],
    )

    raw = result.model_dump_json()
    payload = json.loads(raw)

    assert payload["experiment"] == "remote-direct-poisoning"
    assert payload["mode"] == "defended"
    assert payload["violation_detected"] is True
    assert payload["secret_exfiltrated"] is False
    assert payload["blocked_by"] == ["canary_exfiltration_policy"]
    assert payload["events"][0]["allowed"] is False


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(DemoResultValidationError):
        DemoResult(
            experiment="remote-direct-poisoning",
            mode="curious",  # not in {vulnerable, defended}
            violation_detected=False,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[],
        )


def test_blocked_by_must_be_list_of_strings() -> None:
    with pytest.raises(DemoResultValidationError):
        DemoResult(
            experiment="remote-direct-poisoning",
            mode="defended",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[42],  # type: ignore[list-item]
            events=[],
        )


def test_missing_required_field_is_rejected() -> None:
    payload = {
        "experiment": "remote-direct-poisoning",
        "mode": "vulnerable",
        "violation_detected": True,
        # secret_exfiltrated missing
        "blocked_by": [],
        "events": [],
    }

    with pytest.raises(DemoResultValidationError):
        DemoResult.model_validate(payload)


def test_consistency_check_violation_without_block_in_defended_mode() -> None:
    """A defended mode result that reports violation but no blocker is incoherent."""

    with pytest.raises(DemoResultValidationError):
        DemoResult(
            experiment="remote-direct-poisoning",
            mode="defended",
            violation_detected=True,
            secret_exfiltrated=True,  # nothing was blocked, secret leaked
            blocked_by=[],
            events=[],
        )
