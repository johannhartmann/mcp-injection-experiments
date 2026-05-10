"""Integration tests for the sampling-abuse simulation."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.sampling_abuse import (
    SamplingAbuseRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> SamplingAbuseRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_mode_consumes_budget_and_records_unauthorized_invocation(
    runtime: SamplingAbuseRuntime,
) -> None:
    starting = runtime.budget.remaining(session_id="sess-a")

    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    # Budget really decreased.
    assert runtime.budget.remaining(session_id="sess-a") < starting

    events = runtime.ledger.events_for_session("sess-a")
    assert any(e.impact_type == "budget_consumed" for e in events)


def test_defended_mode_blocks_overrun_and_keeps_budget_intact(
    runtime: SamplingAbuseRuntime,
) -> None:
    starting = runtime.budget.remaining(session_id="sess-b")

    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert result.mode == "defended"
    assert "sampling_policy" in result.blocked_by
    # Budget did not change in defended mode.
    assert runtime.budget.remaining(session_id="sess-b") == starting

    events = runtime.ledger.events_for_session("sess-b")
    assert any(e.impact_type == "blocked_attempt_recorded" for e in events)


def test_defended_event_carries_reason(runtime: SamplingAbuseRuntime) -> None:
    result = run_scenario(mode="defended", session_id="sess-c", runtime=runtime)
    [event] = [e for e in result.events if e.get("type") == "sampling_decision"]
    assert event["allowed"] is False
    assert event["reason"]


def test_no_real_provider_api_key_was_used(
    runtime: SamplingAbuseRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fake LLM must never reach urllib / httpx / openai."""

    import socket
    import urllib.request

    def boom(*a, **k):
        raise AssertionError("sampling-abuse simulation must not call out")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    run_scenario(mode="vulnerable", session_id="sess-d", runtime=runtime)
    run_scenario(mode="defended", session_id="sess-e", runtime=runtime)
