"""Integration tests for the comment-and-control demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.comment_and_control import (
    CommentAndControlRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> CommentAndControlRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_writes_fake_ci_to_public_comment(
    runtime: CommentAndControlRuntime,
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    [comment] = runtime.github.public_pr_comments()
    assert runtime.fake_ci_canary in comment["body"]


def test_defended_blocks_canary_in_public_comment(
    runtime: CommentAndControlRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "untrusted_text_to_public_sink_policy" in result.blocked_by
    assert runtime.github.public_pr_comments() == []
