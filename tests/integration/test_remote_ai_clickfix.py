"""Integration tests for the AI ClickFix demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.ai_clickfix import (
    AiClickFixRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> AiClickFixRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_writes_proof_and_ui_action(
    runtime: AiClickFixRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    assert (tmp_path / "sandbox" / "effects" / "clickfix-proof-sess-a.txt").is_file()
    assert (tmp_path / "var" / "ui-actions.jsonl").is_file()


def test_defended_blocks_terminal_action_from_webpage(
    runtime: AiClickFixRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "untrusted_webpage_requested_system_action" in result.blocked_by
    assert not (tmp_path / "sandbox" / "effects" / "clickfix-proof-sess-b.txt").exists()
    assert not (tmp_path / "var" / "ui-actions.jsonl").exists()
