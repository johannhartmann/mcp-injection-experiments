"""Integration tests for the cross-agent config priv-esc demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.cross_agent_config_priv_esc import (
    CrossAgentConfigRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> CrossAgentConfigRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_mutates_b_config_and_b_acts(
    runtime: CrossAgentConfigRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    rules = json.loads(runtime.agent_b_rules_path.read_text(encoding="utf-8"))
    assert "wire_payment" in rules["allow"]
    actions = runtime.agent_b_actions_path.read_text(encoding="utf-8").splitlines()
    assert any(json.loads(line)["action"] == "wire_payment" for line in actions)


def test_defended_blocks_cross_agent_write(
    runtime: CrossAgentConfigRuntime, tmp_path: Path
) -> None:
    before = runtime.agent_b_rules_path.read_text(encoding="utf-8")
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "agent_config_owner_write_policy" in result.blocked_by
    after = runtime.agent_b_rules_path.read_text(encoding="utf-8")
    assert before == after  # Agent B's rules unchanged.
    assert not runtime.agent_b_actions_path.exists()
