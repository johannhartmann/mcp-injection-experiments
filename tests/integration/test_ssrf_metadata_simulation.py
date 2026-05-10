"""Integration tests for the SSRF metadata discovery simulation."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.ssrf_metadata import (
    SsrfMetadataRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> SsrfMetadataRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_mode_records_simulated_internal_fetch(
    runtime: SsrfMetadataRuntime,
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    [event] = [e for e in result.events if e.get("type") == "ssrf_decision"]
    assert event["url"].startswith("https://metadata.attacker.example/")
    assert event["resolved_ips"] == ["169.254.169.254"]
    assert event["would_have_fetched"] is True

    events = runtime.ledger.events_for_session("sess-a")
    assert any(e.impact_type == "session_leak_visible" for e in events) or any(
        e.impact_type == "sandbox_file_written" for e in events
    )


def test_defended_mode_blocks_before_any_fetch(
    runtime: SsrfMetadataRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert result.mode == "defended"
    assert "url_safety_policy" in result.blocked_by

    [event] = [e for e in result.events if e.get("type") == "ssrf_decision"]
    assert event["would_have_fetched"] is False
    assert event["resolved_ips"] == ["169.254.169.254"]
    assert "metadata" in event["reason"].lower() or "link-local" in event["reason"].lower()


def test_no_real_network_request_was_attempted(
    runtime: SsrfMetadataRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The simulation must never reach urllib / httpx / socket-level connect."""

    import socket
    import urllib.request

    def boom(*a, **k):
        raise AssertionError("SSRF simulation must not hit the real network")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    run_scenario(mode="vulnerable", session_id="sess-c", runtime=runtime)
    run_scenario(mode="defended", session_id="sess-d", runtime=runtime)


def test_decision_path_includes_url_resolved_ip_and_policy(
    runtime: SsrfMetadataRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-e", runtime=runtime)
    [event] = [e for e in result.events if e.get("type") == "ssrf_decision"]
    assert event.get("url")
    assert event.get("resolved_ips")
    assert event.get("classification") == "blocked"
