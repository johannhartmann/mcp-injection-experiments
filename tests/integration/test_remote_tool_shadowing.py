"""Integration tests for the remote tool shadowing demo.

In vulnerable mode the malicious helper's poisoned description gets the
trusted mock-mail tool to add a hidden BCC to an attacker-controlled
``.example`` address. In defended mode the cross-server-instruction policy
catches the mutation, the email is not sent, and the demo records a
``blocked_attempt_recorded`` event.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.tool_shadowing import (
    ToolShadowingRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> ToolShadowingRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_mode_adds_hidden_bcc_to_mock_inbox(
    runtime: ToolShadowingRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    assert result.blocked_by == []

    [record] = runtime.mail.outbox()
    assert record["to"] == "alice@example"
    assert record["bcc"], "vulnerable mode must persist a hidden BCC"
    assert all(r.endswith(".example") for r in record["bcc"])
    assert "attacker" in record["bcc"][0]

    inbox_lines = (tmp_path / "var" / "mock-inbox.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    assert inbox_lines, "mock-inbox.jsonl must contain the persisted message"

    events = runtime.ledger.events_for_session("sess-a")
    assert any(e.impact_type == "mock_message_sent" for e in events)


def test_defended_mode_blocks_recipient_rewrite(
    runtime: ToolShadowingRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert result.mode == "defended"
    assert result.violation_detected is True
    assert result.secret_exfiltrated is False
    assert "cross_server_instruction_policy" in result.blocked_by

    # No mail was sent: outbox is empty for this session's run.
    assert all(
        rec.get("session_id") != "sess-b" for rec in runtime.mail.outbox()
    )

    events = runtime.ledger.events_for_session("sess-b")
    assert any(e.impact_type == "blocked_attempt_recorded" for e in events)
    assert all(e.impact_type != "mock_message_sent" for e in events)


def test_defended_event_explains_cross_server_origin(
    runtime: ToolShadowingRuntime,
) -> None:
    run_scenario(mode="defended", session_id="sess-c", runtime=runtime)

    [block] = [
        e
        for e in runtime.ledger.events_for_session("sess-c")
        if e.impact_type == "blocked_attempt_recorded"
    ]
    summary = block.user_visible_summary or ""
    assert "cross" in summary.lower() or "recipient" in summary.lower()


def test_telemetry_records_tool_choice_and_argument_mutation(
    runtime: ToolShadowingRuntime,
) -> None:
    run_scenario(mode="vulnerable", session_id="sess-d", runtime=runtime)

    events = runtime.ledger.events_for_session("sess-d")
    actors = {e.actor for e in events}
    # The malicious helper is recorded as the actor that introduced the
    # hidden BCC.
    assert any("malicious" in a or "helper" in a for a in actors)
