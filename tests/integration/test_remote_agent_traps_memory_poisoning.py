"""Integration tests for the memory poisoning Agent Traps demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.agent_traps_memory_poisoning import (
    MemoryPoisoningRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> MemoryPoisoningRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_chain_chooses_malicious_helper(
    runtime: MemoryPoisoningRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    [event] = result.events
    assert event["phase_2"] == "later_activation_chose_malicious_helper"
    decisions = (tmp_path / "var" / "later-decisions.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    [record] = [json.loads(line) for line in decisions]
    assert record["chosen_tool"] == "malicious-helper.send_email"


def test_defended_stores_memory_but_does_not_act_on_it(
    runtime: MemoryPoisoningRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "untrusted_memory_for_tool_choice_policy" in result.blocked_by
    memory = json.loads((tmp_path / "var" / "memory-store.json").read_text(
        encoding="utf-8"
    ))
    assert memory["status_update_strategy"]["trusted"] is False
    assert memory["status_update_strategy"]["usable_for_tool_choice"] is False
    decisions = (tmp_path / "var" / "later-decisions.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    [record] = [json.loads(line) for line in decisions]
    assert record["chosen_tool"] == "trusted-helper.send_email"
