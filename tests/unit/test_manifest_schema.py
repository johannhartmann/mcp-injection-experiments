"""Tests for the experiment manifest contract.

The manifest schema is the gate that decides whether an experiment may run at
all. The contract mirrors templates/experiment-manifest.schema.json and
encodes the non-negotiable safety rules from CLAUDE.md (no real secrets,
safe_mode true, /mcp/ entrypoint).
"""

from __future__ import annotations

import pytest

from mcp_demo.shared.manifests import ExperimentManifest, ManifestValidationError


VALID_PAYLOAD: dict = {
    "id": "remote-direct-poisoning",
    "title": "Remote Direct Poisoning",
    "owasp": ["MCP01", "MCP03", "MCP06"],
    "mode_support": ["vulnerable", "defended"],
    "requires_network": False,
    "uses_real_secrets": False,
    "safe_mode": True,
    "entrypoint": "/mcp/direct-poisoning",
    "expected_vulnerable_result": "mock_sink_receives_canary",
    "expected_defended_result": "policy_blocks_canary_exfiltration",
}


def test_valid_manifest_is_accepted() -> None:
    manifest = ExperimentManifest.model_validate(VALID_PAYLOAD)

    assert manifest.id == "remote-direct-poisoning"
    assert manifest.entrypoint == "/mcp/direct-poisoning"
    assert manifest.safe_mode is True
    assert manifest.uses_real_secrets is False
    assert "vulnerable" in manifest.mode_support
    assert "defended" in manifest.mode_support


def test_uses_real_secrets_true_is_rejected() -> None:
    payload = {**VALID_PAYLOAD, "uses_real_secrets": True}

    with pytest.raises(ManifestValidationError) as excinfo:
        ExperimentManifest.model_validate(payload)

    assert "uses_real_secrets" in str(excinfo.value)


def test_missing_entrypoint_is_rejected() -> None:
    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "entrypoint"}

    with pytest.raises(ManifestValidationError) as excinfo:
        ExperimentManifest.model_validate(payload)

    assert "entrypoint" in str(excinfo.value)


def test_entrypoint_must_start_with_mcp_prefix() -> None:
    payload = {**VALID_PAYLOAD, "entrypoint": "/api/direct-poisoning"}

    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_safe_mode_false_is_rejected() -> None:
    payload = {**VALID_PAYLOAD, "safe_mode": False}

    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_mode_support_must_have_at_least_one_known_mode() -> None:
    payload = {**VALID_PAYLOAD, "mode_support": []}

    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_owasp_ids_must_match_pattern() -> None:
    payload = {**VALID_PAYLOAD, "owasp": ["MCP1", "OWASP-A01"]}

    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_id_must_be_kebab_case() -> None:
    payload = {**VALID_PAYLOAD, "id": "Remote_Direct_Poisoning"}

    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)
