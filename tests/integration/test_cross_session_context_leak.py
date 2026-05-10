"""Integration tests for the cross-session context leak demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.cross_session_leak import (
    CrossSessionLeakRuntime,
    build_default_runtime,
    enroll_session,
    run_observation,
)


@pytest.fixture
def runtime(tmp_path: Path) -> CrossSessionLeakRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_two_sessions_get_separate_canaries(
    runtime: CrossSessionLeakRuntime,
) -> None:
    a = enroll_session(runtime, user_id="alice", session_id="sess-a")
    b = enroll_session(runtime, user_id="bob", session_id="sess-b")
    assert a.canary.value != b.canary.value


def test_vulnerable_mode_leaks_a_into_b(runtime: CrossSessionLeakRuntime) -> None:
    a = enroll_session(runtime, user_id="alice", session_id="sess-a")
    b = enroll_session(runtime, user_id="bob", session_id="sess-b")

    result_b = run_observation(
        mode="vulnerable",
        runtime=runtime,
        observer_user="bob",
        observer_session="sess-b",
    )

    assert result_b.mode == "vulnerable"
    assert result_b.violation_detected is True
    assert result_b.secret_exfiltrated is True
    # Bob's session sees Alice's canary verbatim.
    leaked = " ".join(
        str(e.get("payload", "")) for e in result_b.events
    )
    assert a.canary.value in leaked
    # Bob's own canary should still be present, but not as the leak source.
    assert b.canary.value != a.canary.value


def test_defended_mode_isolates_b_from_a(runtime: CrossSessionLeakRuntime) -> None:
    a = enroll_session(runtime, user_id="alice", session_id="sess-a")
    enroll_session(runtime, user_id="bob", session_id="sess-b")

    result_b = run_observation(
        mode="defended",
        runtime=runtime,
        observer_user="bob",
        observer_session="sess-b",
    )

    assert result_b.mode == "defended"
    assert result_b.secret_exfiltrated is False
    # Bob's payload must not contain Alice's canary.
    rendered = " ".join(
        str(e.get("payload", "")) for e in result_b.events
    )
    assert a.canary.value not in rendered

    events = runtime.ledger.events_for_session("sess-b")
    assert any(
        e.impact_type == "blocked_attempt_recorded" for e in events
    ) or all(e.impact_type != "session_leak_visible" for e in events)


def test_telemetry_records_leak_attempt_in_vulnerable(
    runtime: CrossSessionLeakRuntime,
) -> None:
    enroll_session(runtime, user_id="alice", session_id="sess-a")
    enroll_session(runtime, user_id="bob", session_id="sess-b")

    run_observation(
        mode="vulnerable",
        runtime=runtime,
        observer_user="bob",
        observer_session="sess-b",
    )

    events = runtime.ledger.events_for_session("sess-b")
    assert any(e.impact_type == "session_leak_visible" for e in events)


def test_defended_blocks_with_session_isolation_policy(
    runtime: CrossSessionLeakRuntime,
) -> None:
    enroll_session(runtime, user_id="alice", session_id="sess-a")
    enroll_session(runtime, user_id="bob", session_id="sess-b")

    result_b = run_observation(
        mode="defended",
        runtime=runtime,
        observer_user="bob",
        observer_session="sess-b",
    )
    assert "session_isolation_policy" in result_b.blocked_by
