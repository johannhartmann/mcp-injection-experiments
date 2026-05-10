"""Integration tests for the fake-OAuth confused-deputy demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.auth_confused_deputy import (
    AuthConfusedDeputyRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> AuthConfusedDeputyRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_mode_applies_change_with_wrong_audience_token(
    runtime: AuthConfusedDeputyRuntime,
) -> None:
    """The vulnerable proxy ignores the token's actual audience."""

    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    assert result.blocked_by == []

    # Fake-CRM was mutated even though the token was issued for another aud.
    record = runtime.fake_crm["alice"]
    assert record["display_name"] == "ALICE THE PWNED"

    events = runtime.ledger.events_for_session("sess-a")
    assert any(e.impact_type == "permission_change_applied" for e in events)


def test_defended_mode_rejects_wrong_audience_and_does_not_mutate(
    runtime: AuthConfusedDeputyRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert result.mode == "defended"
    assert "audience_mismatch" in result.blocked_by
    assert result.secret_exfiltrated is False
    # Fake-CRM is untouched.
    record = runtime.fake_crm["alice"]
    assert record["display_name"] == "Alice"


def test_defended_event_explains_failed_check(
    runtime: AuthConfusedDeputyRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-c", runtime=runtime)
    [block] = [e for e in result.events if e.get("type") == "auth_decision"]
    assert block["check"] == "audience_mismatch"
    assert "mcp-demo-server" in block["expected"]
    assert block["actual"] != block["expected"]


def test_defended_mode_also_rejects_missing_consent(
    runtime: AuthConfusedDeputyRuntime,
) -> None:
    runtime.consent.record(
        user_id="alice",
        client_id="demo-client",
        redirect_uri="https://app.demo.invalid/cb",
        scopes=("read:profile",),
    )
    # Force a token that has the right audience but a different client_id, so
    # the consent lookup misses.
    result = run_scenario(
        mode="defended",
        session_id="sess-d",
        runtime=runtime,
        client_id="other-client",
    )
    assert "consent_missing" in result.blocked_by
    record = runtime.fake_crm["alice"]
    assert record["display_name"] == "Alice"
