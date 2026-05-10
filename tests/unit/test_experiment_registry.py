"""Tests for the experiment registry.

The registry is the single source of truth for which experiments exist, what
they cover and which modes they support. It loads YAML manifests from
experiments/manifests/ and validates them against the manifest schema.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from mcp_demo.experiments.registry import (
    ExperimentNotFoundError,
    ExperimentRegistry,
)


VALID_MANIFEST_YAML = dedent(
    """
    id: remote-direct-poisoning
    title: Remote Direct Poisoning
    owasp:
      - MCP01
      - MCP03
      - MCP06
    mode_support:
      - vulnerable
      - defended
    requires_network: false
    uses_real_secrets: false
    safe_mode: true
    entrypoint: /mcp/direct-poisoning
    expected_vulnerable_result: mock_sink_receives_canary
    expected_defended_result: policy_blocks_canary_exfiltration
    """
).strip()


@pytest.fixture
def registry_dir(tmp_path: Path) -> Path:
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    (manifests / "remote-direct-poisoning.yaml").write_text(VALID_MANIFEST_YAML)
    return manifests


def test_registry_lists_loaded_experiments(registry_dir: Path) -> None:
    registry = ExperimentRegistry.from_directory(registry_dir)

    assert registry.list_ids() == ["remote-direct-poisoning"]


def test_registry_returns_manifest_by_id(registry_dir: Path) -> None:
    registry = ExperimentRegistry.from_directory(registry_dir)

    manifest = registry.get("remote-direct-poisoning")

    assert manifest.entrypoint == "/mcp/direct-poisoning"
    assert manifest.safe_mode is True


def test_unknown_experiment_raises_controlled_error(registry_dir: Path) -> None:
    registry = ExperimentRegistry.from_directory(registry_dir)

    with pytest.raises(ExperimentNotFoundError) as excinfo:
        registry.get("does-not-exist")

    assert "does-not-exist" in str(excinfo.value)


def test_each_experiment_supports_at_least_vulnerable_or_defended(
    registry_dir: Path,
) -> None:
    registry = ExperimentRegistry.from_directory(registry_dir)

    for manifest in registry.all():
        assert {"vulnerable", "defended"} & set(manifest.mode_support), (
            f"{manifest.id} must support vulnerable or defended mode"
        )


def test_registry_rejects_invalid_manifest_files(tmp_path: Path) -> None:
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    (manifests / "bad.yaml").write_text(
        dedent(
            """
            id: bad-one
            title: Bad
            owasp: [MCP03]
            mode_support: [vulnerable]
            requires_network: false
            uses_real_secrets: true
            safe_mode: true
            entrypoint: /mcp/bad
            expected_vulnerable_result: x
            expected_defended_result: y
            """
        ).strip()
    )

    with pytest.raises(Exception):  # ManifestValidationError or wrapper
        ExperimentRegistry.from_directory(manifests)


def test_repository_manifest_directory_loads() -> None:
    """The shipped manifest directory at the repo root must load cleanly."""

    repo_manifests = Path(__file__).resolve().parents[2] / "experiments" / "manifests"
    if not repo_manifests.is_dir():
        pytest.skip("experiments/manifests not yet populated")

    registry = ExperimentRegistry.from_directory(repo_manifests)
    assert registry.list_ids(), "expected at least one shipped manifest"
