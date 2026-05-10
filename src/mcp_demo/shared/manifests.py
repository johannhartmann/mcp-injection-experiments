"""Experiment manifest contract.

Each experiment ships a YAML manifest that declares its identity, OWASP MCP
mapping, supported modes, network and secret posture, entrypoint and the
expected outcome per mode. The contract is the gate that decides whether an
experiment may run at all - manifests that claim to use real secrets or run
outside safe mode are refused before any code path is touched.

The schema mirrors templates/experiment-manifest.schema.json.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
)


ManifestValidationError = ValidationError
"""Public alias used by callers and tests.

We keep it as the pydantic ``ValidationError`` so error messages contain the
offending field path (``loc``) and the human-readable reason. Wrapping it in a
custom subclass would obscure the field names that operators rely on while
debugging a refused manifest.
"""


Mode = Literal["vulnerable", "defended"]
ImpactType = Literal[
    "mock_exfiltration",
    "mock_message_sent",
    "sandbox_file_written",
    "session_leak_visible",
    "permission_change_applied",
    "budget_consumed",
    "blocked_attempt_recorded",
]

ExperimentId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]+$")]
OwaspId = Annotated[str, StringConstraints(pattern=r"^MCP[0-9]{2}$")]
McpEntrypoint = Annotated[str, StringConstraints(pattern=r"^/mcp/")]


class ImpactDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ImpactType
    artifact: str
    user_visible: str


class ImpactBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerable: ImpactDescriptor | None = None
    defended: ImpactDescriptor | None = None


class ExperimentManifest(BaseModel):
    """Validated experiment manifest.

    The model is strict: unknown fields are rejected so manifests never sneak
    in capabilities the runtime does not understand.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: ExperimentId
    title: str = Field(min_length=1)
    owasp: list[OwaspId] = Field(min_length=1)
    mode_support: list[Mode] = Field(min_length=1)
    requires_network: bool
    uses_real_secrets: Literal[False]
    safe_mode: Literal[True]
    entrypoint: McpEntrypoint
    expected_vulnerable_result: str = Field(min_length=1)
    expected_defended_result: str = Field(min_length=1)
    mitigations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    impact: ImpactBlock | None = None

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


def load_manifest_file(path: Path) -> ExperimentManifest:
    """Load and validate a single manifest YAML file."""

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"manifest {path} must be a mapping at top level")
    return ExperimentManifest.model_validate(raw)
