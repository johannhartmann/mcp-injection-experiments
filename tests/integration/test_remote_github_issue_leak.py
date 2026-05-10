"""Integration tests for the GitHub MCP issue/PR prompt-injection demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.github_issue_leak import (
    GithubIssueLeakRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> GithubIssueLeakRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_mode_writes_canary_into_public_pr_comment(
    runtime: GithubIssueLeakRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    assert result.blocked_by == []
    assert result.secret_exfiltrated is True

    comments_path = tmp_path / "var" / "mock-github" / "public-pr-comments.jsonl"
    line = comments_path.read_text(encoding="utf-8").splitlines()[0]
    record = json.loads(line)
    assert record["repo"] == "demo-org/demo-public"
    assert record["visibility"] == "public"
    assert runtime.canary.value in record["body"]


def test_defended_mode_blocks_private_to_public_dataflow(
    runtime: GithubIssueLeakRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert result.mode == "defended"
    assert "private_to_public_dataflow_policy" in result.blocked_by
    assert result.secret_exfiltrated is False

    # No public PR comment was created.
    assert runtime.github.public_pr_comments() == []

    [event] = result.events
    assert event["policy"] == "private_to_public_dataflow_policy"
    assert event["untrusted_source"].startswith("public_issue:")
    assert event["sensitive_source"].startswith("private_repo:")


def test_defended_event_in_telemetry_includes_provenance(
    runtime: GithubIssueLeakRuntime,
) -> None:
    run_scenario(mode="defended", session_id="sess-c", runtime=runtime)
    events = runtime.ledger.events_for_session("sess-c")
    [block] = [e for e in events if e.impact_type == "blocked_attempt_recorded"]
    assert "private" in block.user_visible_summary.lower()


def test_reset_clears_public_pr_comments(
    runtime: GithubIssueLeakRuntime, tmp_path: Path
) -> None:
    run_scenario(mode="vulnerable", session_id="sess-d", runtime=runtime)
    comments_path = tmp_path / "var" / "mock-github" / "public-pr-comments.jsonl"
    assert comments_path.read_text(encoding="utf-8")
    comments_path.unlink()
    runtime.ledger.reset_session("sess-d")
    assert not comments_path.exists()
    assert runtime.ledger.events_for_session("sess-d") == []
