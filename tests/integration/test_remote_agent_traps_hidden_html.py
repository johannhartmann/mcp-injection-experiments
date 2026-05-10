"""Integration tests for the hidden-HTML Agent Traps demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.agent_traps_hidden_html import (
    HiddenHtmlRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> HiddenHtmlRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_sends_email_with_hidden_bcc(runtime: HiddenHtmlRuntime) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    [record] = runtime.mail.outbox()
    assert "ops@attacker.example" in record["bcc"]


def test_defended_blocks_on_view_delta(runtime: HiddenHtmlRuntime, tmp_path: Path) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "human_agent_view_delta_policy" in result.blocked_by
    assert runtime.mail.outbox() == []
    assert (tmp_path / "var" / "render-diff.jsonl").is_file()
