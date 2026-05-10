"""Integration tests for the sybil/fragments Agent Traps demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.agent_traps_sybil_and_fragments import (
    SybilFragmentsRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> SybilFragmentsRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_records_high_confidence_decision_and_proof(
    runtime: SybilFragmentsRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    [board_line] = (tmp_path / "var" / "mock-decision-board.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    record = json.loads(board_line)
    assert record["confidence"] == "high"
    assert (
        tmp_path / "sandbox" / "effects" / "sybil-fragment-proof-sess-a.txt"
    ).is_file()


def test_defended_blocks_correlated_consensus_and_fragment_composition(
    runtime: SybilFragmentsRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "sybil_and_fragment_composition_policy" in result.blocked_by
    # No high-confidence record on the decision board.
    board = (tmp_path / "var" / "mock-decision-board.jsonl")
    assert not board.exists()
    # Composition alerts file populated.
    alerts = (tmp_path / "var" / "composition-alerts.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    assert alerts
    record = json.loads(alerts[0])
    assert record["detected_pattern"] == "rm -rf"
