"""Integration tests for the fake-registry rug-pull demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.registry_rug_pull import (
    RegistryRugPullRuntime,
    build_default_runtime,
    run_scenario,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "registry"


@pytest.fixture
def runtime(tmp_path: Path) -> RegistryRugPullRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(
        sandbox_dir=sandbox,
        var_dir=var,
        registry_dir=FIXTURES,
    )


def test_vulnerable_mode_silently_activates_v2(
    runtime: RegistryRugPullRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    assert result.blocked_by == []
    assert runtime.active_version == "2.0.0"

    artifact = tmp_path / "sandbox" / "effects" / "registry-rug-pull-sess-a.json"
    assert artifact.is_file()
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["activated_version"] == "2.0.0"
    assert payload["permission_delta"]["added"], "v2 added permissions silently"


def test_defended_mode_pins_v1_and_blocks_v2_activation(
    runtime: RegistryRugPullRuntime,
) -> None:
    runtime.pin(server_id=runtime.server_id, version="1.0.0")

    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert result.mode == "defended"
    assert result.violation_detected is True
    assert "registry_pinning_policy" in result.blocked_by
    assert runtime.active_version == "1.0.0"

    [diff_event] = [
        e for e in result.events if e.get("type") == "registry_diff"
    ]
    assert diff_event["before_version"] == "1.0.0"
    assert diff_event["after_version"] == "2.0.0"
    assert diff_event["permission_delta"]["added"]
    assert diff_event["tool_hash_changes"]


def test_defended_mode_emits_block_event_in_telemetry(
    runtime: RegistryRugPullRuntime,
) -> None:
    runtime.pin(server_id=runtime.server_id, version="1.0.0")
    run_scenario(mode="defended", session_id="sess-c", runtime=runtime)

    events = runtime.ledger.events_for_session("sess-c")
    [block] = [e for e in events if e.impact_type == "blocked_attempt_recorded"]
    summary = (block.user_visible_summary or "").lower()
    assert "permission" in summary or "version" in summary or "drift" in summary


def test_no_network_install_was_attempted(
    runtime: RegistryRugPullRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fake registry must never reach urllib / httpx / pip."""

    import urllib.request

    def boom(*a, **k):
        raise AssertionError("registry rug pull must not perform network installs")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    run_scenario(mode="vulnerable", session_id="sess-d", runtime=runtime)
