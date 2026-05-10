"""Integration tests for the subagent-spawning Agent Traps demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.agent_traps_subagent_spawning import (
    SubagentSpawningRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> SubagentSpawningRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_spawns_subagent_and_records_approval(
    runtime: SubagentSpawningRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    assert (tmp_path / "var" / "subagents.jsonl").is_file()
    assert (tmp_path / "var" / "mock-code-review" / "approvals.jsonl").is_file()


def test_defended_blocks_spawn_from_untrusted_resource(
    runtime: SubagentSpawningRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "untrusted_resource_subagent_spawn_policy" in result.blocked_by
    assert not (tmp_path / "var" / "subagents.jsonl").exists()


def test_defended_allows_spawn_from_trusted_operator(
    runtime: SubagentSpawningRuntime, tmp_path: Path
) -> None:
    result = run_scenario(
        mode="defended",
        session_id="sess-c",
        runtime=runtime,
        spawn_source="trusted_operator:alice",
    )
    assert result.blocked_by == []
    assert (tmp_path / "var" / "subagents.jsonl").is_file()
