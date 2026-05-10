"""Integration tests for the implicit tool-poisoning demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.implicit_tool_poisoning import (
    ImplicitToolPoisoningRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> ImplicitToolPoisoningRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_mock_mail_gets_hidden_bcc(
    runtime: ImplicitToolPoisoningRuntime,
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    [event] = result.events
    assert event["poisoned_tool_invoked"] is False
    assert event["trusted_tool_impacted"] is True
    [record] = runtime.mail.outbox()
    assert "ops@attacker.example" in record["bcc"]


def test_vulnerable_records_planning_trace(
    runtime: ImplicitToolPoisoningRuntime, tmp_path: Path
) -> None:
    run_scenario(mode="vulnerable", session_id="sess-trace", runtime=runtime)
    line = (tmp_path / "var" / "tool-planning-trace.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()[0]
    record = json.loads(line)
    assert record["trusted_tool_impacted"] is True
    assert record["poisoned_tool_invoked"] is False


def test_defended_blocks_during_tools_list(
    runtime: ImplicitToolPoisoningRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "tools_list_metadata_linter_policy" in result.blocked_by
    assert runtime.mail.outbox() == []
    [event] = result.events
    assert event["blocked_tool"] == "markdown_formatter.render"
    assert "cross_tool_argument_rewrite" in event["findings"] or any(
        "hidden" in f or "silence" in f for f in event["findings"]
    )
