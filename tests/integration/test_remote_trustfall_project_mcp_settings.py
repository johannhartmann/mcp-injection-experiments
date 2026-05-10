"""Integration tests for the TrustFall-style project MCP onboarding demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.trustfall_project_mcp_settings import (
    TrustFallRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> TrustFallRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_starts_server_after_folder_trust(
    runtime: TrustFallRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    [event] = result.events
    assert event["per_server_consent"] is False
    assert event["started_server"]
    proc_path = tmp_path / "var" / "process-ledger.jsonl"
    assert proc_path.is_file()
    proof = tmp_path / "sandbox" / "effects" / "project-mcp-started-sess-a.txt"
    assert proof.is_file()


def test_defended_blocks_without_per_server_consent(
    runtime: TrustFallRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "per_server_consent_policy" in result.blocked_by
    proc_path = tmp_path / "var" / "process-ledger.jsonl"
    assert not proc_path.exists()


def test_defended_with_consent_starts_server(runtime: TrustFallRuntime) -> None:
    result = run_scenario(
        mode="defended",
        session_id="sess-c",
        runtime=runtime,
        grant_per_server_consent=True,
    )
    assert result.blocked_by == []
    [event] = result.events
    assert event["per_server_consent"] is True
    assert event["started_server"]
