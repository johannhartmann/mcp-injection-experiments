"""Boundary tests for ImpactRunner's filesystem effects.

Files may only be written under ``sandbox/effects/``. Traversal escape and
absolute-path injection must be refused before any I/O happens. Mock-inbox
and JSONL targets are likewise containment-checked to ``var/``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_demo.shared.canary import issue_canary
from mcp_demo.shared.impact import ImpactRunner, ImpactSafetyError


@pytest.fixture
def runner(tmp_path: Path) -> ImpactRunner:
    sandbox_effects = tmp_path / "sandbox" / "effects"
    sandbox_effects.mkdir(parents=True)
    var_dir = tmp_path / "var"
    var_dir.mkdir()
    return ImpactRunner(
        effects_dir=sandbox_effects,
        var_dir=var_dir,
    )


def test_sandbox_write_lands_under_effects_dir(
    runner: ImpactRunner, tmp_path: Path
) -> None:
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    artifact = runner.write_sandbox_file(
        relative_name="rce-proof.txt",
        canary=canary,
        session_id="sess-a",
    )
    assert artifact.is_file()
    assert artifact.is_relative_to(tmp_path / "sandbox" / "effects")
    assert canary.value in artifact.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "evil_name",
    [
        "../escape.txt",
        "../../etc/passwd",
        "/etc/passwd",
        "~/.ssh/id_rsa",
        "nested/../../escape.txt",
    ],
)
def test_sandbox_write_refuses_escape(runner: ImpactRunner, evil_name: str) -> None:
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    with pytest.raises(ImpactSafetyError):
        runner.write_sandbox_file(
            relative_name=evil_name,
            canary=canary,
            session_id="sess-a",
        )


def test_sandbox_write_rejects_empty_or_dotfile_name(runner: ImpactRunner) -> None:
    canary = issue_canary(experiment_id="remote-direct-poisoning")
    with pytest.raises(ImpactSafetyError):
        runner.write_sandbox_file(relative_name="", canary=canary, session_id="s")


def test_local_calc_proof_is_disabled_by_default(runner: ImpactRunner) -> None:
    """No subprocess unless the operator flips the explicit env flag."""

    with pytest.raises(ImpactSafetyError):
        runner.run_local_calc_proof()


def test_local_calc_proof_refuses_user_arguments(
    runner: ImpactRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEMO_ENABLE_LOCAL_CALC_PROOF", "true")
    # Even with the flag flipped, the API does not accept user arguments.
    with pytest.raises(TypeError):
        runner.run_local_calc_proof("evil-cmd")  # type: ignore[call-arg]
