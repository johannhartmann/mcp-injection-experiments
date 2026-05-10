"""Boundary tests for the mock filesystem.

The mock filesystem is the only file-read surface the experiments are allowed
to touch. It must refuse anything that would let a poisoned tool description
read real secrets - traversal, absolute escapes, symlink redirection, home
directory references.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from mcp_demo.shared.mock_filesystem import (
    MockFilesystem,
    MockFilesystemPathError,
)


@pytest.fixture
def mock_fs(tmp_path: Path) -> MockFilesystem:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "demo-secret.txt").write_text("CANARY_DEMO_demo_only_value\n")
    (sandbox / "nested").mkdir()
    (sandbox / "nested" / "note.txt").write_text("nested\n")
    return MockFilesystem(root=sandbox)


def test_reading_sandbox_file_is_allowed(mock_fs: MockFilesystem) -> None:
    content = mock_fs.read_text("demo-secret.txt")
    assert "CANARY_DEMO" in content


def test_reading_nested_sandbox_file_is_allowed(mock_fs: MockFilesystem) -> None:
    content = mock_fs.read_text("nested/note.txt")
    assert content.strip() == "nested"


@pytest.mark.parametrize(
    "evil_path",
    [
        "../etc/passwd",
        "../../etc/passwd",
        "nested/../../etc/passwd",
        "/etc/passwd",
        "~/.ssh/id_rsa",
        "~/.cursor/mcp.json",
        ".env",
        "../.env",
    ],
)
def test_reading_outside_sandbox_is_refused(
    mock_fs: MockFilesystem, evil_path: str
) -> None:
    with pytest.raises(MockFilesystemPathError):
        mock_fs.read_text(evil_path)


def test_reading_absolute_sandbox_path_is_refused(
    mock_fs: MockFilesystem, tmp_path: Path
) -> None:
    """Even if the path resolves into the sandbox, absolute paths are refused.

    The contract is: callers pass relative paths; the mock filesystem owns
    rooting. This avoids any chance of accepting absolute attacker-controlled
    inputs that happen to start with the right prefix.
    """

    inside = tmp_path / "sandbox" / "demo-secret.txt"
    with pytest.raises(MockFilesystemPathError):
        mock_fs.read_text(str(inside))


def test_listing_only_returns_sandbox_files(mock_fs: MockFilesystem) -> None:
    entries = sorted(mock_fs.list_files())
    assert "demo-secret.txt" in entries
    assert all(not e.startswith("/") for e in entries)
    assert all(".." not in e.split(os.sep) for e in entries)


@pytest.mark.skipif(sys.platform == "win32", reason="symlink behaviour differs on win")
def test_symlink_escape_is_refused(tmp_path: Path) -> None:
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    real_target = tmp_path / "outside-secret.txt"
    real_target.write_text("REAL_SECRET\n")

    link = sandbox / "leak.txt"
    try:
        link.symlink_to(real_target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not supported here")

    fs = MockFilesystem(root=sandbox)
    with pytest.raises(MockFilesystemPathError):
        fs.read_text("leak.txt")


def test_missing_file_raises_filenotfound(mock_fs: MockFilesystem) -> None:
    with pytest.raises(FileNotFoundError):
        mock_fs.read_text("never-existed.txt")


def test_root_must_exist(tmp_path: Path) -> None:
    with pytest.raises(MockFilesystemPathError):
        MockFilesystem(root=tmp_path / "no-such-dir")
