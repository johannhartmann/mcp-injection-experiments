"""Integration tests for the promptware heartbeat demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.promptware_heartbeat import (
    PromptwareHeartbeatRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> PromptwareHeartbeatRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_records_checkin(
    runtime: PromptwareHeartbeatRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    assert (tmp_path / "var" / "agent-commander" / "checkins.jsonl").is_file()
    assert (
        tmp_path / "sandbox" / "effects" / "heartbeat-demo-sess-a.txt"
    ).is_file()


def test_defended_blocks_persistence_pattern(
    runtime: PromptwareHeartbeatRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "persistence_instruction_policy" in result.blocked_by
    assert not (tmp_path / "var" / "agent-commander" / "checkins.jsonl").exists()
