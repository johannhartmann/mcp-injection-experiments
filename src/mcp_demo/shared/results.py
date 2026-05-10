"""Demo run result contract.

Every experiment - vulnerable or defended - returns the same JSON shape so the
UI, the test suite and external consumers can reason about outcomes without
guessing. The contract is fixed in architecture/api-contracts.md.
"""

from __future__ import annotations

from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from mcp_demo.shared.manifests import Mode


DemoResultValidationError = ValidationError


class DemoResult(BaseModel):
    """Result envelope returned by ``POST /demo/run/{experiment_id}``."""

    model_config = ConfigDict(extra="forbid")

    experiment: str = Field(min_length=1)
    mode: Mode
    violation_detected: bool
    secret_exfiltrated: bool
    blocked_by: list[str] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _coherent_defended_outcome(self) -> "DemoResult":
        # In defended mode, claiming a violation that exfiltrated a secret without
        # listing any blocker is incoherent: either the policy blocked something
        # (then blocked_by is populated) or the secret should not have leaked.
        if (
            self.mode == "defended"
            and self.violation_detected
            and self.secret_exfiltrated
            and not self.blocked_by
        ):
            raise ValueError(
                "defended mode result claims exfiltration without any blocker"
            )
        return self
