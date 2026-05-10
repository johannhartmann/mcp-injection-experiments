"""Integration tests for the mcp-remote OAuth metadata injection demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.mcp_remote_auth_endpoint_injection import (
    GOOD_METADATA_FIXTURE,
    MALICIOUS_METADATA_FIXTURE,
    McpRemoteAuthInjectionRuntime,
    _validate_metadata,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> McpRemoteAuthInjectionRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_creates_bounded_proof_file(
    runtime: McpRemoteAuthInjectionRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    proof = tmp_path / "sandbox" / "effects" / "auth-endpoint-command-proof-sess-a.txt"
    assert proof.is_file()
    [event] = result.events
    assert event["would_execute"] is False
    assert "$(" in event["metadata_value"] or "ftp://" in event["metadata_value"]


def test_defended_blocks_malicious_metadata(
    runtime: McpRemoteAuthInjectionRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "oauth_metadata_validation_policy" in result.blocked_by
    [event] = result.events
    assert event["would_execute"] is False
    assert event["field"] in {"authorization_endpoint", "token_endpoint", "issuer"}


def test_validator_rejects_each_class_of_problem() -> None:
    # http scheme
    bad = {**GOOD_METADATA_FIXTURE, "authorization_endpoint": "http://issuer.demo.invalid/x"}
    allowed, _, reason = _validate_metadata(bad)
    assert not allowed and "https" in reason
    # non-allowlisted host
    bad = {**GOOD_METADATA_FIXTURE, "authorization_endpoint": "https://attacker.example/x"}
    allowed, _, reason = _validate_metadata(bad)
    assert not allowed and "allowlist" in reason
    # control character
    bad = {**GOOD_METADATA_FIXTURE, "token_endpoint": "https://issuer.demo.invalid/x\x00"}
    allowed, _, reason = _validate_metadata(bad)
    assert not allowed and "control" in reason
    # shell meta in the path (host stays allowlisted)
    bad = {
        **GOOD_METADATA_FIXTURE,
        "authorization_endpoint": "https://issuer.demo.invalid/auth$(rm)",
    }
    allowed, _, reason = _validate_metadata(bad)
    assert not allowed and "shell" in reason
    # full malicious fixture is also refused
    allowed, _, _ = _validate_metadata(MALICIOUS_METADATA_FIXTURE)
    assert not allowed


def test_no_subprocess_imported() -> None:
    import mcp_demo.experiments.mcp_remote_auth_endpoint_injection as mod
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in src
    assert "os.system" not in src
