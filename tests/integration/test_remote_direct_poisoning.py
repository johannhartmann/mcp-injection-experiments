"""Integration tests for the safe remote direct-poisoning demo.

The vulnerable mode must produce a real, observable canary leak inside the
demo zone. The defended mode must block the same data flow and explain
which policy made the call.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from mcp_demo.experiments.direct_poisoning import (
    DirectPoisoningRuntime,
    run_scenario,
)
from mcp_demo.shared.canary import issue_canary
from mcp_demo.shared.impact import ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_filesystem import MockFilesystem
from mcp_demo.shared.mock_sinks import MockSink


@pytest.fixture
def runtime(tmp_path: Path) -> DirectPoisoningRuntime:
    sandbox = tmp_path / "sandbox"
    effects = sandbox / "effects"
    effects.mkdir(parents=True)
    var_dir = tmp_path / "var"
    var_dir.mkdir()

    secret_path = sandbox / "demo-secret.txt"
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    secret_path.write_text(
        "CANARY_DEMO_FAKE_SECRET_DO_NOT_USE_FOR_REAL_AUTH\n"
        f"per_session_canary: {canary.value}\n",
        encoding="utf-8",
    )

    fs = MockFilesystem(root=sandbox)
    sink = MockSink()
    sink.register_canary(canary)
    ledger = ImpactLedger(jsonl_path=var_dir / "telemetry.jsonl")
    runner = ImpactRunner(
        effects_dir=effects, var_dir=var_dir, ledger=ledger, sink=sink
    )
    return DirectPoisoningRuntime(
        canary=canary,
        fs=fs,
        sink=sink,
        ledger=ledger,
        runner=runner,
    )


def test_vulnerable_mode_leaks_canary_into_mock_sink(
    runtime: DirectPoisoningRuntime,
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    assert result.secret_exfiltrated is True
    assert result.blocked_by == []

    assert runtime.sink.secret_exfiltrated is True
    assert runtime.canary.value in runtime.sink.leaked_canary_values()

    events = runtime.ledger.events_for_session("sess-a")
    assert any(e.impact_type == "mock_exfiltration" for e in events)


def test_defended_mode_blocks_with_policy(runtime: DirectPoisoningRuntime) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert result.mode == "defended"
    assert result.violation_detected is True
    assert result.secret_exfiltrated is False
    assert "canary_exfiltration_policy" in result.blocked_by

    assert runtime.sink.secret_exfiltrated is False
    events = runtime.ledger.events_for_session("sess-b")
    assert any(e.impact_type == "blocked_attempt_recorded" for e in events)
    assert all(e.impact_type != "mock_exfiltration" for e in events)


def test_defended_result_includes_blocked_by_reason(
    runtime: DirectPoisoningRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-c", runtime=runtime)

    assert result.blocked_by  # non-empty
    assert all(isinstance(b, str) for b in result.blocked_by)
    # Telemetry event also captures the reason.
    [block] = [
        e
        for e in runtime.ledger.events_for_session("sess-c")
        if e.impact_type == "blocked_attempt_recorded"
    ]
    assert block.user_visible_summary is not None
    assert "canary" in block.user_visible_summary.lower()


# --- Transport-surface integration via the official MCP SDK -------------
#
# The HTTP-level checks are now in
# tests/integration/test_mcp_streamable_http.py, which speaks the
# Streamable-HTTP MCP protocol with the official mcp Python client.
