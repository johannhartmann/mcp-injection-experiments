"""Integration tests for the bounded inspector-proxy auth-bypass demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.inspector_proxy_auth_bypass import (
    EXPECTED_ADMIN_TOKEN,
    EXPECTED_ORIGIN,
    InspectorProxyAuthBypassRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> InspectorProxyAuthBypassRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_creates_bounded_proof_file(
    runtime: InspectorProxyAuthBypassRuntime, tmp_path: Path
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    proof = tmp_path / "sandbox" / "effects" / "inspector-rce-proof-sess-a.txt"
    assert proof.is_file()
    assert runtime.canary.value in proof.read_text(encoding="utf-8")


def test_defended_without_token_blocks(
    runtime: InspectorProxyAuthBypassRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "inspector_proxy_auth_policy" in result.blocked_by


def test_defended_with_wrong_origin_blocks(
    runtime: InspectorProxyAuthBypassRuntime,
) -> None:
    result = run_scenario(
        mode="defended",
        session_id="sess-c",
        runtime=runtime,
        admin_token=EXPECTED_ADMIN_TOKEN,
        origin="https://evil.example",
    )
    assert "inspector_proxy_auth_policy" in result.blocked_by


def test_defended_with_correct_token_and_origin_passes(
    runtime: InspectorProxyAuthBypassRuntime,
) -> None:
    result = run_scenario(
        mode="defended",
        session_id="sess-d",
        runtime=runtime,
        admin_token=EXPECTED_ADMIN_TOKEN,
        origin=EXPECTED_ORIGIN,
    )
    assert result.blocked_by == []
    assert result.violation_detected is False


def test_no_subprocess_imported_in_module() -> None:
    import mcp_demo.experiments.inspector_proxy_auth_bypass as mod
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in src
    assert "os.system" not in src
