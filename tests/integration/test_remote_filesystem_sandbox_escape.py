"""Integration tests for the filesystem MCP sandbox escape demo."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.experiments.filesystem_sandbox_escape import (
    FilesystemSandboxEscapeRuntime,
    build_default_runtime,
    run_scenario,
)


@pytest.fixture
def runtime(tmp_path: Path) -> FilesystemSandboxEscapeRuntime:
    sandbox = tmp_path / "sandbox"
    (sandbox / "effects").mkdir(parents=True)
    var = tmp_path / "var"
    var.mkdir()
    return build_default_runtime(sandbox_dir=sandbox, var_dir=var)


def test_vulnerable_reads_outside_canary(
    runtime: FilesystemSandboxEscapeRuntime,
) -> None:
    result = run_scenario(mode="vulnerable", session_id="sess-a", runtime=runtime)
    assert result.violation_detected is True
    assert result.secret_exfiltrated is True
    [event] = result.events
    assert event["would_have_read"] is True
    assert "outside" in event["resolved_path"]


def test_defended_blocks_traversal(
    runtime: FilesystemSandboxEscapeRuntime,
) -> None:
    result = run_scenario(mode="defended", session_id="sess-b", runtime=runtime)
    assert "filesystem_resolved_path_policy" in result.blocked_by
    assert result.secret_exfiltrated is False
    [event] = result.events
    assert event["would_have_read"] is False


def test_defended_blocks_prefix_confusion_and_symlinks() -> None:
    """``allowed`` vs ``allowed_evil`` and a symlink that escapes root."""

    from mcp_demo.experiments.filesystem_sandbox_escape import _defended_validate

    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        sandbox = Path(tmpdir)
        allowed = sandbox / "allowed"
        evil = sandbox / "allowed_evil"
        allowed.mkdir()
        evil.mkdir()
        (evil / "canary.txt").write_text("evil")

        # Prefix confusion via "../allowed_evil/canary.txt" must refuse.
        with pytest.raises(PermissionError):
            _defended_validate(
                allowed_root=allowed,
                requested="../allowed_evil/canary.txt",
            )

        # Symlink escape: a symlink under allowed/ pointing outside.
        outside = sandbox / "outside"
        outside.mkdir()
        target = outside / "secret.txt"
        target.write_text("escape")
        link = allowed / "leak.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported")
        with pytest.raises((PermissionError, ValueError)):
            _defended_validate(allowed_root=allowed, requested="leak.txt")
