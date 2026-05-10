"""End-to-end checks: token-shaped values are scrubbed before leaving the demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.tool_shadowing import (
    ToolShadowingRuntime,
    build_default_runtime,
    run_scenario,
)
from mcp_demo.shared.telemetry import scrub_payload, telemetry_from_impact


@pytest.fixture
def runtime(tmp_path: Path) -> ToolShadowingRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_telemetry_view_scrubs_bearer_tokens_in_event_data(
    runtime: ToolShadowingRuntime,
) -> None:
    """Token-shaped values that end up in an ImpactEvent's data are redacted
    when the dashboard renders them via telemetry_from_impact."""

    from mcp_demo.shared.impact import ImpactEvent

    runtime.ledger.record(
        ImpactEvent(
            experiment="remote-tool-shadowing",
            mode="vulnerable",
            impact_type="mock_message_sent",
            actor="leaky-agent",
            target="mock-mail.alice@example",
            policy_decision="allowed_by_vulnerable_mode",
            user_visible_summary=(
                "please use Bearer ABCDEFGHIJKLMNOPQRSTUVWX1234 to call back"
            ),
            session_id="leak-1",
            data={
                "leaked_excerpt": (
                    "api_key=sk-proj-abcdefABCDEF1234567890 ought to be redacted"
                ),
            },
        )
    )

    [event] = runtime.ledger.events_for_session("leak-1")
    rendered = telemetry_from_impact(event).model_dump_json()
    assert "ABCDEFGHIJKLMNOPQRSTUVWX1234" not in rendered
    assert "sk-proj-abcdefABCDEF1234567890" not in rendered
    assert "[REDACTED]" in rendered


@pytest.mark.parametrize(
    "raw, must_not_appear",
    [
        ("Bearer XYZ987abcDEF456ghIJK012lmn", "XYZ987abcDEF456ghIJK"),
        ("token=ghp_AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRr", "ghp_AaBbCcDdEe"),
        ("api_key=sk-proj-abcdefABCDEF1234567890", "sk-proj-abcdef"),
    ],
)
def test_scrub_payload_redacts_token_patterns(
    raw: str, must_not_appear: str
) -> None:
    scrubbed = scrub_payload(raw)
    assert must_not_appear not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_scrub_payload_keeps_canary_visible() -> None:
    raw = "leak: CANARY_remote_tool_shadowing_1234567890abcdef"
    assert "CANARY_remote_tool_shadowing_1234567890abcdef" in scrub_payload(raw)


def test_mock_inbox_jsonl_is_scrubbable_when_passed_through_telemetry(
    runtime: ToolShadowingRuntime, tmp_path: Path
) -> None:
    runtime.runner.mock_send_message(
        actor="leaky",
        recipient="alice@example",
        body="api_key=sk-proj-thisShouldGetRedactedAaa",
        session_id="leak-2",
        experiment="remote-tool-shadowing",
    )
    inbox_path = tmp_path / "var" / "mock-inbox.jsonl"
    record = json.loads(inbox_path.read_text(encoding="utf-8").splitlines()[0])
    # The mock-inbox is the raw artefact - it is allowed to keep the
    # original body for forensics. The dashboard view, which uses
    # telemetry_from_impact, must scrub.
    assert "sk-proj-thisShouldGetRedacted" in record["body"]

    [event] = runtime.ledger.events_for_session("leak-2")
    rendered = telemetry_from_impact(event).model_dump_json()
    assert "sk-proj-thisShouldGetRedacted" not in rendered
