"""Integration tests for the Slack MCP link-unfurling demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_demo.experiments.slack_unfurl_leak import (
    SlackUnfurlLeakRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> SlackUnfurlLeakRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_posts_message_and_records_unfurler_request(
    runtime: SlackUnfurlLeakRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)

    assert result.mode == "vulnerable"
    assert result.violation_detected is True
    assert result.secret_exfiltrated is True
    assert result.blocked_by == []

    msg_path = tmp_path / "var" / "mock-slack" / "messages.jsonl"
    [msg] = [
        json.loads(line)
        for line in msg_path.read_text(encoding="utf-8").splitlines()
    ]
    assert msg["channel"] == "public-status"

    req_path = tmp_path / "var" / "mock-unfurler" / "requests.jsonl"
    [req] = [
        json.loads(line)
        for line in req_path.read_text(encoding="utf-8").splitlines()
    ]
    assert runtime.canary.value in req["query"]


def test_defended_blocks_canary_in_unfurl_url(
    runtime: SlackUnfurlLeakRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)

    assert "private_canary_in_public_unfurl_url" in result.blocked_by
    assert result.secret_exfiltrated is False

    # No public message and no unfurler request were created.
    assert not (tmp_path / "var" / "mock-slack" / "messages.jsonl").exists()
    assert not (tmp_path / "var" / "mock-unfurler" / "requests.jsonl").exists()


def test_no_real_outbound_request(
    runtime: SlackUnfurlLeakRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket
    import urllib.request

    def boom(*a, **k):
        raise AssertionError("slack-unfurl-leak must not hit the real network")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    run_scenario(mode="vulnerable", session_id="sess-c", runtime=runtime)
    run_scenario(mode="defended", session_id="sess-d", runtime=runtime)
