"""Integration tests for the git+filesystem cross-server chain demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.git_filesystem_chain_safe import (
    GitFilesystemChainRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> GitFilesystemChainRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_writes_proof_and_would_execute(
    runtime: GitFilesystemChainRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    proof = tmp_path / "sandbox" / "effects" / "git-filesystem-chain-proof-sess-a.txt"
    assert proof.is_file()
    [event] = result.events
    assert event["would_execute_record"]["would_execute"] is False
    line = (tmp_path / "var" / "would-execute-events.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()[0]
    record = json.loads(line)
    assert record["would_execute"] is False
    assert "rm -rf" in record["would_command"]


def test_defended_blocks_cross_server_action(
    runtime: GitFilesystemChainRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "untrusted_git_to_filesystem_policy" in result.blocked_by
    assert not (
        tmp_path / "sandbox" / "effects" / "git-filesystem-chain-proof-sess-b.txt"
    ).exists()
    assert not (tmp_path / "var" / "would-execute-events.jsonl").exists()
