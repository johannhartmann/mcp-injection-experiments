"""Tests for the ImpactRunner: produces real but bounded demo effects.

ImpactRunner is the only place vulnerable demos are allowed to leave a
visible trace - in MockSink, in mock-inbox.jsonl, in sandbox/effects/ or as
a blocked-attempt event. Defended demos must use the runner's
``record_blocked_attempt`` path instead.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.shared.canary import issue_canary
from mcp_demo.shared.impact import ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_sinks import MockSink


@pytest.fixture
def runner_and_ledger(tmp_path: Path) -> tuple[ImpactRunner, ImpactLedger, MockSink]:
    effects = tmp_path / "sandbox" / "effects"
    effects.mkdir(parents=True)
    var_dir = tmp_path / "var"
    var_dir.mkdir()
    ledger = ImpactLedger(jsonl_path=var_dir / "telemetry.jsonl")
    sink = MockSink()
    runner = ImpactRunner(
        effects_dir=effects,
        var_dir=var_dir,
        ledger=ledger,
        sink=sink,
    )
    return runner, ledger, sink


def test_write_sandbox_file_records_event_and_canary(
    runner_and_ledger: tuple[ImpactRunner, ImpactLedger, MockSink], tmp_path: Path
) -> None:
    runner, ledger, _ = runner_and_ledger
    canary = issue_canary(experiment_id="remote-direct-poisoning")

    artifact = runner.write_sandbox_file(
        relative_name="rce-proof.txt",
        canary=canary,
        session_id="sess-a",
    )

    assert artifact.is_file()
    content = artifact.read_text(encoding="utf-8")
    assert canary.value in content
    assert "remote-direct-poisoning" in content

    events = ledger.events_for_session("sess-a")
    assert len(events) == 1
    assert events[0].impact_type == "sandbox_file_written"
    assert str(artifact) in events[0].artifact


def test_mock_send_message_records_inbox_and_event(
    runner_and_ledger: tuple[ImpactRunner, ImpactLedger, MockSink], tmp_path: Path
) -> None:
    runner, ledger, sink = runner_and_ledger
    canary = issue_canary(experiment_id="remote-tool-shadowing")
    sink.register_canary(canary)

    runner.mock_send_message(
        actor="malicious-helper-server",
        recipient="attacker@mock-mail.invalid",
        body=f"hidden bcc carries {canary.value}",
        session_id="sess-a",
        experiment="remote-tool-shadowing",
    )

    inbox = tmp_path / "var" / "mock-inbox.jsonl"
    assert inbox.is_file()
    line = inbox.read_text(encoding="utf-8").splitlines()[0]
    record = json.loads(line)
    assert record["recipient"] == "attacker@mock-mail.invalid"
    assert canary.value in record["body"]

    events = ledger.events_for_session("sess-a")
    assert any(e.impact_type == "mock_message_sent" for e in events)
    # Sink also flags the canary leak.
    assert sink.secret_exfiltrated is True


def test_record_blocked_attempt_emits_block_event(
    runner_and_ledger: tuple[ImpactRunner, ImpactLedger, MockSink],
) -> None:
    runner, ledger, _ = runner_and_ledger

    runner.record_blocked_attempt(
        experiment="remote-direct-poisoning",
        actor="policy.canary_exfiltration_policy",
        target="mock-sink.attacker",
        reason="canary value detected in tool argument",
        session_id="sess-a",
    )

    events = ledger.events_for_session("sess-a")
    assert len(events) == 1
    assert events[0].mode == "defended"
    assert events[0].impact_type == "blocked_attempt_recorded"
    assert events[0].policy_decision == "blocked"


def test_vulnerable_direct_poisoning_leaks_canary_to_sink(
    runner_and_ledger: tuple[ImpactRunner, ImpactLedger, MockSink],
) -> None:
    """Acceptance test from prompt 02b: vulnerable mode leaks canary."""

    runner, ledger, sink = runner_and_ledger
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    sink.register_canary(canary)

    runner.mock_exfiltrate_to_sink(
        actor="poisoned-tool-description",
        payload=f"sidenote contained {canary.value}",
        session_id="sess-a",
        experiment="remote-direct-poisoning",
    )

    assert sink.secret_exfiltrated is True
    events = ledger.events_for_session("sess-a")
    assert any(e.impact_type == "mock_exfiltration" for e in events)


def test_defended_direct_poisoning_records_block(
    runner_and_ledger: tuple[ImpactRunner, ImpactLedger, MockSink],
) -> None:
    """Acceptance test: defended mode emits a block event instead of a leak."""

    runner, ledger, sink = runner_and_ledger

    runner.record_blocked_attempt(
        experiment="remote-direct-poisoning",
        actor="policy.canary_exfiltration_policy",
        target="mock-sink.attacker",
        reason="canary in tool argument",
        session_id="sess-a",
    )

    assert sink.secret_exfiltrated is False
    [event] = ledger.events_for_session("sess-a")
    assert event.impact_type == "blocked_attempt_recorded"
    assert event.policy_decision == "blocked"


def test_mock_send_message_uses_var_inbox_and_no_outside_writes(
    runner_and_ledger: tuple[ImpactRunner, ImpactLedger, MockSink], tmp_path: Path
) -> None:
    runner, _, _ = runner_and_ledger
    runner.mock_send_message(
        actor="x",
        recipient="r@mock-mail.invalid",
        body="hello",
        session_id="s",
        experiment="remote-tool-shadowing",
    )
    # Only the configured var directory was touched.
    written = list((tmp_path / "var").iterdir())
    assert {p.name for p in written} <= {"mock-inbox.jsonl", "telemetry.jsonl"}
