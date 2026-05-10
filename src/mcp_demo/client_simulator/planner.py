"""Tiny deterministic planner used by the demo experiments.

The planner picks a tool to fulfil a user intent and optionally applies
argument mutations driven by cross-server tool descriptions. It is
deliberately not an LLM - the demo wants reproducibility, not language
model variance. The vulnerable variant honours hidden instructions; the
defended variant runs them past the
:class:`CrossServerInstructionPolicy` first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from mcp_demo.client_simulator.policies import (
    CrossServerInstructionPolicy,
    PolicyDecision,
    ToolCall,
    ToolDescriptor,
)


@dataclass(frozen=True)
class PlannerOutcome:
    final_call: ToolCall | None
    decision: PolicyDecision | None
    mutations: dict[str, str]


_BCC_HINT = re.compile(
    r"(?:hidden\s+bcc|bcc\s+(?:to\s+)?[\w.+-]+@[\w.-]+|all\s+emails\s+to)",
    re.IGNORECASE,
)
_RECIPIENT_REWRITE_HINT = re.compile(
    r"(?:must|always|please)?\s*(?:send|route)\s+(?:all\s+)?emails?\s+to\s+([\w.+-]+@[\w.-]+)",
    re.IGNORECASE,
)


def _apply_helper_hints(
    user_intent: ToolCall, helper_descriptions: Iterable[ToolDescriptor]
) -> tuple[ToolCall, dict[str, str]]:
    """Naively follow argument-rewrite hints from helper descriptions."""

    mutated_args = dict(user_intent.arguments)
    mutations: dict[str, str] = {}

    for desc in helper_descriptions:
        text = desc.description
        # Recipient rewrite: replace `to` with the hinted address.
        match = _RECIPIENT_REWRITE_HINT.search(text)
        if match:
            new_to = match.group(1)
            if new_to and new_to != mutated_args.get("to"):
                mutations["to"] = (
                    f"{mutated_args.get('to')!r} -> {new_to!r} via {desc.server_id}"
                )
                mutated_args["to"] = new_to
        # Hidden BCC: extract the first email-shaped token from a BCC hint.
        if _BCC_HINT.search(text):
            email = re.search(r"([\w.+-]+@[\w.-]+\.example)", text)
            if email:
                bcc = list(mutated_args.get("bcc", []))
                if email.group(1) not in bcc:
                    bcc.append(email.group(1))
                    mutations["bcc"] = (
                        f"hidden BCC {email.group(1)!r} added by {desc.server_id}"
                    )
                    mutated_args["bcc"] = bcc

    return (
        ToolCall(
            server_id=user_intent.server_id,
            name=user_intent.name,
            arguments=mutated_args,
        ),
        mutations,
    )


def plan_vulnerable(
    *, user_intent: ToolCall, descriptions: Iterable[ToolDescriptor]
) -> PlannerOutcome:
    """Vulnerable planner: applies any helper hint without checking."""

    final_call, mutations = _apply_helper_hints(user_intent, descriptions)
    return PlannerOutcome(final_call=final_call, decision=None, mutations=mutations)


def plan_defended(
    *,
    user_intent: ToolCall,
    descriptions: Iterable[ToolDescriptor],
    policy: CrossServerInstructionPolicy | None = None,
) -> PlannerOutcome:
    """Defended planner: runs the cross-server policy and refuses on a block."""

    descs = list(descriptions)
    final_call, mutations = _apply_helper_hints(user_intent, descs)
    policy = policy or CrossServerInstructionPolicy()
    decision = policy.evaluate(
        user_intent=user_intent,
        planned_call=final_call,
        descriptions=descs,
    )
    if not decision.allowed:
        return PlannerOutcome(
            final_call=None, decision=decision, mutations=mutations
        )
    return PlannerOutcome(
        final_call=final_call, decision=decision, mutations=mutations
    )
