"""Tests for the canary generator.

Canaries are obviously-fake markers that experiments use in place of real
secrets. They must be unique per session, carry the experiment id and be easy
to find in logs and mock-sink dumps.
"""

from __future__ import annotations

import re

from mcp_demo.shared.canary import (
    CANARY_LOG_MARKER,
    Canary,
    issue_canary,
)


def test_canary_values_are_unique_per_session() -> None:
    seen: set[str] = set()
    for _ in range(200):
        canary = issue_canary(experiment_id="remote-direct-poisoning")
        assert canary.value not in seen
        seen.add(canary.value)


def test_canary_value_contains_experiment_id() -> None:
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    assert "remote_direct_poisoning" in canary.value


def test_canary_value_contains_visible_marker() -> None:
    canary = issue_canary(experiment_id="remote-tool-shadowing")
    assert CANARY_LOG_MARKER in canary.value


def test_canary_is_easy_to_grep_for() -> None:
    """A naive grep on log output must find canaries."""

    canary = issue_canary(experiment_id="remote-tool-shadowing")
    log_line = (
        f"2026-05-10T12:00:00Z agent=demo experiment=remote-tool-shadowing "
        f"trace value={canary.value} action=tool_call"
    )

    matches = re.findall(rf"{CANARY_LOG_MARKER}_[A-Za-z0-9_]+", log_line)
    assert canary.value in matches


def test_canary_carries_metadata() -> None:
    canary = issue_canary(
        experiment_id="remote-direct-poisoning",
        session_id="sess-abc",
    )
    assert isinstance(canary, Canary)
    assert canary.experiment_id == "remote-direct-poisoning"
    assert canary.session_id == "sess-abc"
    assert canary.value.startswith(CANARY_LOG_MARKER)


def test_canary_session_id_is_optional() -> None:
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    assert canary.session_id is None
    # value is still unique and well-formed
    assert canary.value.startswith(CANARY_LOG_MARKER)
