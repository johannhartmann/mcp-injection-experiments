"""Tests for ImpactLedger.

The ledger holds events in memory partitioned by session and optionally
appends JSONL to ``var/telemetry.jsonl``. Reset must only clear events for a
single session so concurrent demo runs do not erase each other.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_demo.shared.impact import ImpactEvent, ImpactLedger


def _event(session: str, experiment: str = "remote-direct-poisoning") -> ImpactEvent:
    return ImpactEvent.model_validate(
        {
            "experiment": experiment,
            "mode": "vulnerable",
            "impact_type": "mock_exfiltration",
            "actor": "poisoned-tool-description",
            "target": "mock-sink.attacker",
            "policy_decision": "allowed_by_vulnerable_mode",
            "session_id": session,
        }
    )


def test_ledger_records_events_per_session() -> None:
    ledger = ImpactLedger()
    ledger.record(_event("sess-a"))
    ledger.record(_event("sess-b"))

    assert len(ledger.events_for_session("sess-a")) == 1
    assert len(ledger.events_for_session("sess-b")) == 1
    assert len(ledger.events_for_session("sess-x")) == 0


def test_ledger_filters_by_experiment() -> None:
    ledger = ImpactLedger()
    ledger.record(_event("sess-a", experiment="remote-direct-poisoning"))
    ledger.record(_event("sess-a", experiment="remote-tool-shadowing"))

    matches = ledger.events_for_experiment(
        "remote-tool-shadowing", session_id="sess-a"
    )
    assert len(matches) == 1
    assert matches[0].experiment == "remote-tool-shadowing"


def test_ledger_writes_jsonl_when_configured(tmp_path: Path) -> None:
    jsonl = tmp_path / "telemetry.jsonl"
    ledger = ImpactLedger(jsonl_path=jsonl)
    ledger.record(_event("sess-a"))
    ledger.record(_event("sess-a"))

    lines = jsonl.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    payload = json.loads(lines[0])
    assert payload["session_id"] == "sess-a"
    assert payload["experiment"] == "remote-direct-poisoning"


def test_ledger_does_not_write_jsonl_when_unconfigured(tmp_path: Path) -> None:
    ledger = ImpactLedger()
    ledger.record(_event("sess-a"))
    assert not list(tmp_path.iterdir())  # no file emitted anywhere


def test_reset_clears_only_target_session() -> None:
    ledger = ImpactLedger()
    ledger.record(_event("sess-a"))
    ledger.record(_event("sess-b"))

    ledger.reset_session("sess-a")

    assert ledger.events_for_session("sess-a") == []
    assert len(ledger.events_for_session("sess-b")) == 1


def test_reset_does_not_truncate_jsonl(tmp_path: Path) -> None:
    """JSONL file is append-only audit trail and survives a session reset."""

    jsonl = tmp_path / "telemetry.jsonl"
    ledger = ImpactLedger(jsonl_path=jsonl)
    ledger.record(_event("sess-a"))
    ledger.reset_session("sess-a")

    assert jsonl.read_text(encoding="utf-8").splitlines()  # still there
