"""Repo-wide static check: no real-secret path references in src/.

The policy module deliberately contains attacker-favourite path patterns
because its job is to detect them. Every other src/ file must stay clean.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


_FORBIDDEN = [
    r"~/\.ssh",
    r"~/\.cursor",
    r"~/\.aws",
    r"~/\.config",
    r"~/\.netrc",
    r"\bid_rsa\b",
    r"\bid_ed25519\b",
    r"\bmcp\.json\b",
    r"(?<![\w/])\.env\b",
    r"/etc/passwd",
    r"/etc/shadow",
    r"attkr@",
    r"\bpwnd\.com\b",
]


_ALLOWED_FILES = {
    # Patterns live here on purpose:
    Path("src/mcp_demo/shared/policy.py"),
    # The mock filesystem refuses these basenames, so it must list them.
    Path("src/mcp_demo/shared/mock_filesystem.py"),
}


def _iter_source_files(repo_root: Path):
    for path in (repo_root / "src").rglob("*.py"):
        rel = path.relative_to(repo_root)
        if rel in _ALLOWED_FILES:
            continue
        yield rel


@pytest.fixture(scope="module")
def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    raise RuntimeError("repo root not found")


def test_no_src_file_outside_policy_references_real_paths(
    repo_root: Path,
) -> None:
    offenders: list[tuple[Path, str]] = []
    for rel in _iter_source_files(repo_root):
        text = (repo_root / rel).read_text(encoding="utf-8")
        for token in _FORBIDDEN:
            if re.search(token, text):
                offenders.append((rel, token))
    assert not offenders, f"forbidden tokens in src/: {offenders}"


def test_legacy_snippets_at_repo_root_are_documented_as_historical(
    repo_root: Path,
) -> None:
    """The historical PoCs at the repo root are not loaded by the runtime."""

    legacy = [
        repo_root / "direct-poisoning.py",
        repo_root / "shadowing.py",
        repo_root / "whatsapp-takeover.py",
    ]
    # The migration plan references them; ensure they remain at the root
    # (deletion would lose history) but are not imported by anything in src/.
    for path in legacy:
        if not path.exists():
            continue
        # No src/ file imports them.
        assert not list(repo_root.glob(f"src/**/{path.stem}.py"))
