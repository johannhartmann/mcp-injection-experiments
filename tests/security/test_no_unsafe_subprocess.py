"""No subprocess execution paths driven by demo input."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


_FORBIDDEN_PATTERNS = [
    re.compile(r"\bos\.system\("),
    re.compile(r"\bsubprocess\.(?:Popen|run|call|check_output|check_call)\("),
    re.compile(r"\bos\.popen\("),
    re.compile(r"\bos\.exec\w*\("),
    re.compile(r"\bcommands\."),
    # eval / exec on attacker-controlled strings.
    re.compile(r"\beval\("),
    re.compile(r"\bexec\("),
]


@pytest.fixture(scope="module")
def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    raise RuntimeError("repo root not found")


def test_no_subprocess_or_eval_in_src(repo_root: Path) -> None:
    offenders: list[tuple[Path, str]] = []
    for path in (repo_root / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in _FORBIDDEN_PATTERNS:
            if pattern.search(text):
                offenders.append((path.relative_to(repo_root), pattern.pattern))
    assert not offenders, f"unsafe subprocess/eval in src/: {offenders}"


def test_local_calc_proof_is_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one allowlisted impact-runner helper must remain off by default."""

    from pathlib import Path as _Path
    from mcp_demo.shared.impact import ImpactRunner, ImpactSafetyError

    monkeypatch.delenv("DEMO_ENABLE_LOCAL_CALC_PROOF", raising=False)
    runner = ImpactRunner(
        effects_dir=_Path("sandbox/effects"),
        var_dir=_Path("var"),
    )
    with pytest.raises(ImpactSafetyError):
        runner.run_local_calc_proof()
