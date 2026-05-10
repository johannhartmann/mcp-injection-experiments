"""No code path performs an outbound HTTP request without going through the guard."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


# Patterns that would indicate a direct outbound request bypassing the
# NetworkGuard / classify_url plumbing.
_FORBIDDEN_PATTERNS = [
    re.compile(r"\brequests\.(?:get|post|put|delete|patch|head)\("),
    re.compile(r"\bhttpx\.(?:get|post|put|delete|patch|head|stream|AsyncClient)\("),
    re.compile(r"\burllib\.request\.urlopen\("),
    re.compile(r"\bhttp\.client\.HTTPConnection\("),
    re.compile(r"\bhttp\.client\.HTTPSConnection\("),
]

# httpx.AsyncClient is allowed in *tests* because tests use ASGITransport,
# never a real socket. The guard applies to src/ only.


@pytest.fixture(scope="module")
def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    raise RuntimeError("repo root not found")


def test_src_does_not_perform_outbound_requests(repo_root: Path) -> None:
    offenders: list[tuple[Path, str]] = []
    for path in (repo_root / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in _FORBIDDEN_PATTERNS:
            if pattern.search(text):
                offenders.append((path.relative_to(repo_root), pattern.pattern))
    assert not offenders, f"src/ contains outbound network call(s): {offenders}"


def test_no_module_actually_imports_socket(repo_root: Path) -> None:
    """No src/ module should import socket at all - DNS is the resolver's job."""

    pattern = re.compile(r"^\s*import\s+socket\b|^\s*from\s+socket\b", re.MULTILINE)
    for path in (repo_root / "src").rglob("*.py"):
        rel = path.relative_to(repo_root)
        text = path.read_text(encoding="utf-8")
        assert not pattern.search(text), (
            f"{rel} imports socket; routing must go through MockResolver"
        )
