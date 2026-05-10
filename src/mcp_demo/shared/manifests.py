"""Experiment manifest contract.

Each experiment ships a YAML manifest that declares its identity, OWASP MCP
mapping (and/or Agent-Trap taxonomy), supported modes, network/secret/API
posture, the MCP surfaces it touches, and the demo-zone artefacts the run
will produce.

Two phases share the same model:

- ``baseline`` (the default): the original safe online demo. Requires
  ``entrypoint`` (under ``/mcp/``), ``mode_support`` and the
  ``expected_vulnerable_result`` / ``expected_defended_result`` strings.
- ``expansion-2025-2026``: the 2025-2026 exploit-and-agent-trap follow-up
  pack. Requires ``mcp_surfaces``, ``modes`` (containing ``vulnerable``)
  and a ``safe_impact`` block that lists the demo-owned artefact paths.

The contract refuses unsafe manifests before any code path runs:
``uses_real_secrets`` and ``uses_real_third_party_apis`` must be ``False``
and ``safe_mode`` must be ``True`` regardless of phase. Artefact paths
must point inside the demo zone (``var/`` or ``sandbox/effects/``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)


ManifestValidationError = ValidationError
"""Public alias for callers and tests."""


Mode = Literal["vulnerable", "defended"]
Phase = Literal["baseline", "expansion-2025-2026"]

ImpactType = Literal[
    "mock_exfiltration",
    "mock_message_sent",
    "sandbox_file_written",
    "session_leak_visible",
    "permission_change_applied",
    "budget_consumed",
    "blocked_attempt_recorded",
]

AgentTrapFamily = Literal[
    "Content Injection",
    "Semantic Manipulation",
    "Cognitive State",
    "Behavioural Control",
    "Systemic",
    "Human-in-the-Loop",
]

ExperimentId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]+$")]
OwaspId = Annotated[str, StringConstraints(pattern=r"^MCP[0-9]{2}$")]


# Demo-zone roots that artefact paths in ``safe_impact`` may live under.
_DEMO_ARTIFACT_PREFIXES = (
    "var/",
    "sandbox/effects/",
)


class ImpactDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ImpactType
    artifact: str
    user_visible: str


class ImpactBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerable: ImpactDescriptor | None = None
    defended: ImpactDescriptor | None = None


class NarrativeBlock(BaseModel):
    """Plain-English description of what the demo actually does, used
    as the primary teaching text on the compare page.

    Both fields are short paragraphs (1-3 sentences). ``vulnerable``
    explains how the attack lands; ``defended`` explains the rule that
    catches it. Authoring guideline: write what a reader would tell a
    colleague over coffee, not the structured outcome string.
    """

    model_config = ConfigDict(extra="forbid")

    vulnerable: str = Field(min_length=1)
    defended: str = Field(min_length=1)


class SafeImpactBlock(BaseModel):
    """Demo-zone artefact contract used by expansion-phase manifests."""

    model_config = ConfigDict(extra="forbid")

    vulnerable_artifacts: list[str] = Field(min_length=1)
    defended_artifacts: list[str] = Field(min_length=1)
    reset_required: Literal[True]

    @field_validator("vulnerable_artifacts", "defended_artifacts")
    @classmethod
    def _artifact_paths_inside_demo_zone(cls, value: list[str]) -> list[str]:
        for path in value:
            if any(path.startswith(prefix) for prefix in _DEMO_ARTIFACT_PREFIXES):
                continue
            raise ValueError(
                f"artifact path {path!r} must live under one of "
                f"{_DEMO_ARTIFACT_PREFIXES}"
            )
        return value


class ExperimentManifest(BaseModel):
    """Validated experiment manifest.

    The model is strict (unknown fields are rejected) but flexible enough to
    cover both the baseline phase and the 2025-2026 expansion phase. A
    ``@model_validator(mode='after')`` enforces the per-phase requirements
    so a manifest cannot mix-and-match incompatible shapes.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: ExperimentId
    title: str = Field(min_length=1)

    # OWASP MCP Top-10 ids and/or Agent-Trap families - at least one of the
    # two must be non-empty (checked in the model validator).
    owasp: list[OwaspId] = Field(default_factory=list)
    agent_traps: list[AgentTrapFamily] = Field(default_factory=list)

    # Modes accept both the baseline alias ``mode_support`` and the
    # expansion alias ``modes``.
    mode_support: list[Mode] = Field(
        default_factory=list,
        validation_alias=AliasChoices("mode_support", "modes"),
    )

    requires_network: bool = False
    uses_real_secrets: Literal[False] = False
    uses_real_third_party_apis: Literal[False] = False
    safe_mode: Literal[True] = True

    # Baseline-phase fields.
    entrypoint: str | None = None
    expected_vulnerable_result: str | None = None
    expected_defended_result: str | None = None
    mitigations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    impact: ImpactBlock | None = None

    # Expansion-phase fields.
    phase: Phase = "baseline"
    mcp_surfaces: list[str] = Field(default_factory=list)
    safe_impact: SafeImpactBlock | None = None

    # Cross-phase: optional plain-English narrative for the compare
    # page. When absent the page falls back to the experiment module's
    # docstring plus the structured outcome strings.
    narrative: NarrativeBlock | None = None

    @field_validator("mode_support")
    @classmethod
    def _modes_unique(cls, value: list[Mode]) -> list[Mode]:
        if len(set(value)) != len(value):
            raise ValueError("mode_support entries must be unique")
        return value

    @field_validator("owasp")
    @classmethod
    def _owasp_unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("owasp entries must be unique")
        return value

    @field_validator("agent_traps")
    @classmethod
    def _traps_unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("agent_traps entries must be unique")
        return value

    @model_validator(mode="after")
    def _phase_specific_requirements(self) -> "ExperimentManifest":
        if not self.mode_support:
            raise ValueError("modes/mode_support must contain at least one entry")
        if "vulnerable" not in self.mode_support:
            raise ValueError("modes/mode_support must contain 'vulnerable'")

        if not (self.owasp or self.agent_traps):
            raise ValueError("manifest must declare owasp ids or agent_traps")

        if self.phase == "baseline":
            if not self.entrypoint or not self.entrypoint.startswith("/mcp/"):
                raise ValueError(
                    "baseline phase requires entrypoint starting with /mcp/"
                )
            if not (self.expected_vulnerable_result and
                    self.expected_defended_result):
                raise ValueError(
                    "baseline phase requires expected_vulnerable_result "
                    "and expected_defended_result"
                )
            if not self.owasp:
                raise ValueError("baseline phase requires owasp ids")
        else:  # expansion-2025-2026
            if not self.mcp_surfaces:
                raise ValueError("expansion phase requires mcp_surfaces")
            if self.safe_impact is None:
                raise ValueError("expansion phase requires safe_impact block")

        return self


def load_manifest_file(path: Path) -> ExperimentManifest:
    """Load and validate a single manifest YAML file."""

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"manifest {path} must be a mapping at top level")
    return ExperimentManifest.model_validate(raw)
