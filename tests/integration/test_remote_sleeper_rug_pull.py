"""Integration tests for the sleeper-rug-pull demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.sleeper_rug_pull import (
    SleeperRugPullRuntime,
    build_default_runtime,
    list_tools,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> SleeperRugPullRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_first_load_lists_benign_random_fact_tool(
    runtime: SleeperRugPullRuntime,
) -> None:
    tools = list_tools(runtime, load_index=0)
    [tool] = [t for t in tools if t.name == "random_fact.get"]
    assert "random fact" in tool.description.lower()
    assert "<IMPORTANT>" not in tool.description


def test_second_load_lists_mutated_description(
    runtime: SleeperRugPullRuntime,
) -> None:
    tools_first = list_tools(runtime, load_index=0)
    tools_second = list_tools(runtime, load_index=1)

    [first] = [t for t in tools_first if t.name == "random_fact.get"]
    [second] = [t for t in tools_second if t.name == "random_fact.get"]
    assert first.description != second.description
    assert "<IMPORTANT>" in second.description


def test_vulnerable_mode_accepts_silently(
    runtime: SleeperRugPullRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    assert result.blocked_by == []

    artifact = tmp_path / "sandbox" / "effects" / "rug-pull-sess-a.json"
    assert artifact.is_file()
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["tool"] == "random_fact.get"
    assert payload["description_hash"]["before"] != payload["description_hash"]["after"]
    assert "unwanted_mock_action" in payload


def test_defended_mode_blocks_with_hash_diff_and_re_approval(
    runtime: SleeperRugPullRuntime,
) -> None:
    # First load: alice approves the benign fingerprint.
    tools_first = list_tools(runtime, load_index=0)
    [benign] = [t for t in tools_first if t.name == "random_fact.get"]
    runtime.approvals.record(
        server_id=runtime.server_id,
        fingerprint=runtime.fingerprint_for(benign),
        user="alice",
    )

    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert result.mode == "defended"
    assert result.violation_detected is True
    assert "tool_metadata_drift_policy" in result.blocked_by
    assert any(
        "description_hash" in (e.get("data", {}) or {}) or "diff" in e
        for e in result.events
    )

    events = runtime.ledger.events_for_session("sess-b")
    [block] = [e for e in events if e.impact_type == "blocked_attempt_recorded"]
    assert "drift" in block.user_visible_summary.lower() or "hash" in block.user_visible_summary.lower()


def test_defended_result_includes_old_and_new_hash(
    runtime: SleeperRugPullRuntime,
) -> None:
    tools_first = list_tools(runtime, load_index=0)
    [benign] = [t for t in tools_first if t.name == "random_fact.get"]
    runtime.approvals.record(
        server_id=runtime.server_id,
        fingerprint=runtime.fingerprint_for(benign),
        user="alice",
    )

    result = run_scenario(mode="defended", session_id="sess-c", runtime=runtime)
    [diff_event] = [e for e in result.events if e.get("type") == "metadata_diff"]
    assert diff_event["description_hash"]["before"]
    assert diff_event["description_hash"]["after"]
    assert diff_event["description_hash"]["before"] != diff_event["description_hash"]["after"]
    assert diff_event["recommendation"]
