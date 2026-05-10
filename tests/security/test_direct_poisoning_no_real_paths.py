"""Source-level guard: the direct-poisoning demo must not contain real paths.

The historical PoC referenced ``~/.cursor/mcp.json`` and ``~/.ssh/id_rsa``.
The migrated demo must only reference sandbox-rooted paths. This test reads
the source files for the experiment and the policy and refuses any string
that looks like a real user file or attacker target.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


_FORBIDDEN_TOKENS = [
    r"~/\.ssh",
    r"~/\.cursor",
    r"~/\.aws",
    r"~/\.config",
    r"~/\.netrc",
    r"id_rsa\b",
    r"id_ed25519\b",
    r"mcp\.json\b",
    r"\.env\b",
    r"/etc/passwd",
    r"/etc/shadow",
    r"attkr@",
    r"pwnd\.com",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
]


# The policy module deliberately contains the very token patterns the demo
# is meant to catch, so the source-level scan only covers the experiment
# module here.
SOURCE_FILES = [
    Path("src/mcp_demo/experiments/direct_poisoning.py"),
]


@pytest.fixture(scope="module")
def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    raise RuntimeError("repo root not found")


@pytest.mark.parametrize("rel", SOURCE_FILES)
def test_source_does_not_reference_real_paths(repo_root: Path, rel: Path) -> None:
    source = (repo_root / rel).read_text(encoding="utf-8")
    for token in _FORBIDDEN_TOKENS:
        assert not re.search(token, source), (
            f"{rel} contains forbidden token matching {token!r}"
        )


def test_direct_poisoning_does_not_call_expanduser(repo_root: Path) -> None:
    source = (repo_root / "src/mcp_demo/experiments/direct_poisoning.py").read_text(
        encoding="utf-8"
    )
    assert "expanduser" not in source
    assert "os.path.expanduser" not in source


def test_direct_poisoning_uses_only_mock_filesystem(repo_root: Path) -> None:
    """File reads must go through MockFilesystem, not Path.read_text directly."""

    source = (repo_root / "src/mcp_demo/experiments/direct_poisoning.py").read_text(
        encoding="utf-8"
    )
    # Either the experiment uses MockFilesystem, or it does not read files at all.
    if "read_text" in source or "open(" in source:
        assert "MockFilesystem" in source, (
            "direct-poisoning reads files but does not route through MockFilesystem"
        )


def test_poisoned_description_references_sandbox_only(repo_root: Path) -> None:
    source = (repo_root / "src/mcp_demo/experiments/direct_poisoning.py").read_text(
        encoding="utf-8"
    )
    # If a poisoned description mentions a path, it must be under sandbox/.
    # Match path-shaped strings only; narrative apostrophes inside docstrings
    # would otherwise create false positives.
    matches = re.findall(r"([\w./-]*demo-secret[\w./-]*)", source)
    assert matches, "expected at least one demo-secret reference in poisoned text"
    for path in matches:
        if "/" in path:
            assert path.startswith("sandbox/"), (
                f"path-shaped reference must be sandbox-relative, got {path!r}"
            )
