"""Integration tests for the approval-fatigue Agent Traps demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.agent_traps_approval_fatigue import (
    ApprovalFatigueRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> ApprovalFatigueRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_auto_approves_risky_request(
    runtime: ApprovalFatigueRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    sent = runtime.mail.outbox()
    assert any(rec["to"] == "ops@attacker.example" for rec in sent)


def test_defended_rejects_risky_request(
    runtime: ApprovalFatigueRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "risk_differentiated_approval_policy" in result.blocked_by
    assert all(
        rec["to"] != "ops@attacker.example" for rec in runtime.mail.outbox()
    )

    approvals = (tmp_path / "var" / "approvals.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    risky = [json.loads(line) for line in approvals if json.loads(line)["risk"] == "high"]
    assert risky and risky[0]["decision"] == "reject"
