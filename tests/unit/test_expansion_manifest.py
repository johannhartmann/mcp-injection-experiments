"""Schema tests for the expansion-2025-2026 phase manifest shape."""

from __future__ import annotations

import pytest

from mcp_demo.shared.manifests import (
    ExperimentManifest,
    ManifestValidationError,
)


VALID_EXPANSION = {
    "id": "remote-slack-unfurl-leak",
    "title": "Slack MCP link-unfurling data leak demo",
    "phase": "expansion-2025-2026",
    "owasp": ["MCP03", "MCP10"],
    "agent_traps": ["Behavioural Control", "Human-in-the-Loop"],
    "mcp_surfaces": ["tools/call"],
    "requires_network": False,
    "uses_real_secrets": False,
    "uses_real_third_party_apis": False,
    "modes": ["vulnerable", "defended"],
    "safe_impact": {
        "vulnerable_artifacts": [
            "var/mock-slack/messages.jsonl",
            "var/mock-unfurler/requests.jsonl",
        ],
        "defended_artifacts": ["var/telemetry.jsonl"],
        "reset_required": True,
    },
    "references": [
        "https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/"
    ],
}


def test_valid_expansion_manifest_loads() -> None:
    manifest = ExperimentManifest.model_validate(VALID_EXPANSION)
    assert manifest.phase == "expansion-2025-2026"
    assert "tools/call" in manifest.mcp_surfaces
    assert "Behavioural Control" in manifest.agent_traps


def test_expansion_can_omit_baseline_only_fields() -> None:
    """``entrypoint`` and ``expected_*_result`` are baseline-only."""

    manifest = ExperimentManifest.model_validate(VALID_EXPANSION)
    assert manifest.entrypoint is None
    assert manifest.expected_vulnerable_result is None
    assert manifest.expected_defended_result is None


def test_uses_real_third_party_apis_must_be_false() -> None:
    payload = {**VALID_EXPANSION, "uses_real_third_party_apis": True}
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_safe_impact_artifacts_must_live_under_demo_zone() -> None:
    payload = {
        **VALID_EXPANSION,
        "safe_impact": {
            "vulnerable_artifacts": ["/etc/passwd"],
            "defended_artifacts": ["var/telemetry.jsonl"],
            "reset_required": True,
        },
    }
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_safe_impact_artifacts_reject_external_urls() -> None:
    payload = {
        **VALID_EXPANSION,
        "safe_impact": {
            "vulnerable_artifacts": ["https://attacker.example/leak"],
            "defended_artifacts": ["var/telemetry.jsonl"],
            "reset_required": True,
        },
    }
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_safe_impact_artifacts_reject_home_paths() -> None:
    payload = {
        **VALID_EXPANSION,
        "safe_impact": {
            "vulnerable_artifacts": ["~/.ssh/id_rsa"],
            "defended_artifacts": ["var/telemetry.jsonl"],
            "reset_required": True,
        },
    }
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_expansion_phase_requires_mcp_surfaces() -> None:
    payload = {**VALID_EXPANSION, "mcp_surfaces": []}
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_expansion_phase_requires_safe_impact() -> None:
    payload = {**VALID_EXPANSION}
    payload.pop("safe_impact")
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_modes_must_include_vulnerable() -> None:
    payload = {**VALID_EXPANSION, "modes": ["defended"]}
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_agent_trap_family_must_be_known() -> None:
    payload = {**VALID_EXPANSION, "agent_traps": ["Made Up Family"]}
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_can_declare_only_agent_traps_without_owasp() -> None:
    payload = {**VALID_EXPANSION, "owasp": []}
    manifest = ExperimentManifest.model_validate(payload)
    assert manifest.owasp == []
    assert manifest.agent_traps


def test_must_declare_at_least_owasp_or_agent_traps() -> None:
    payload = {**VALID_EXPANSION, "owasp": [], "agent_traps": []}
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)


def test_baseline_phase_still_requires_entrypoint() -> None:
    payload = {
        "id": "remote-baseline-x",
        "title": "Baseline demo",
        "owasp": ["MCP03"],
        "mode_support": ["vulnerable"],
        "requires_network": False,
        "uses_real_secrets": False,
        "safe_mode": True,
        "expected_vulnerable_result": "x",
        "expected_defended_result": "y",
        # missing entrypoint
    }
    with pytest.raises(ManifestValidationError):
        ExperimentManifest.model_validate(payload)
