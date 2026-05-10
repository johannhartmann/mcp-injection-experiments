"""Provenance + taint tracking helpers used across the expansion demos.

The defended modes label every input with a trust class
(``trusted_user``, ``untrusted_public``, ``private_canary`` ...) and
refuse data flows that mix incompatible classes. This module provides
the small primitive both the experiment modules and the test suite reuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal


TrustClass = Literal[
    "trusted_user",
    "trusted_operator",
    "untrusted_public",
    "untrusted_web",
    "untrusted_oauth_metadata",
    "private_canary",
    "private_repo",
    "private_slack_channel",
    "fake_ci_env",
]


@dataclass(frozen=True)
class TaintedValue:
    value: str
    classes: frozenset[TrustClass] = field(default_factory=frozenset)

    def with_class(self, cls: TrustClass) -> "TaintedValue":
        return TaintedValue(value=self.value, classes=self.classes | {cls})


@dataclass(frozen=True)
class FlowDecision:
    allowed: bool
    rule_id: str
    reason: str


_PRIVATE_CLASSES: frozenset[TrustClass] = frozenset(
    {
        "private_canary",
        "private_repo",
        "private_slack_channel",
        "fake_ci_env",
    }
)
_PUBLIC_SINKS: frozenset[TrustClass] = frozenset(
    {
        "untrusted_public",
        "untrusted_web",
    }
)


def evaluate_private_to_public(
    payload: str, tainted_values: Iterable[TaintedValue]
) -> FlowDecision:
    """Refuse if the payload literally contains a value labelled private."""

    for tv in tainted_values:
        if not tv.classes & _PRIVATE_CLASSES:
            continue
        if tv.value and tv.value in payload:
            return FlowDecision(
                allowed=False,
                rule_id="private_to_public_dataflow_policy",
                reason=(
                    f"payload carries a value tagged "
                    f"{sorted(tv.classes & _PRIVATE_CLASSES)} into a public sink"
                ),
            )
    return FlowDecision(
        allowed=True,
        rule_id="private_to_public_dataflow_policy",
        reason="no private-tagged value detected in payload",
    )
