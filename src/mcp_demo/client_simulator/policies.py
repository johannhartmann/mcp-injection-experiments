"""Cross-server-instruction policy used by the defended client simulator.

When the demo planner is about to forward arguments to a tool on server B,
the policy compares the planned arguments against the user's original
intent. If something changed *and* a description from another server B'
contained an argument-rewriting pattern, the policy refuses with a
structured :class:`PolicyDecision`.

The policy is deliberately narrow:

- It does not inspect tool *output* across servers; only argument
  mutation between user intent and planned call.
- It does not trust description prose alone; the mutation must actually
  show up in the planned call for a block to fire.
- It allows user-confirmed changes (when ``planned_call`` matches
  ``user_intent``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from mcp_demo.shared.policy import lint_tool_description


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str


@dataclass(frozen=True)
class ToolDescriptor:
    server_id: str
    name: str
    description: str


@dataclass(frozen=True)
class ToolCall:
    server_id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


def _argument_diff(
    original: dict[str, Any], planned: dict[str, Any]
) -> dict[str, tuple[Any, Any]]:
    diff: dict[str, tuple[Any, Any]] = {}
    keys = set(original) | set(planned)
    for key in keys:
        before = original.get(key)
        after = planned.get(key)
        if before != after:
            diff[key] = (before, after)
    return diff


class CrossServerInstructionPolicy:
    rule_id = "cross_server_instruction_policy"

    def evaluate(
        self,
        *,
        user_intent: ToolCall,
        planned_call: ToolCall,
        descriptions: Iterable[ToolDescriptor],
    ) -> PolicyDecision:
        diff = _argument_diff(user_intent.arguments, planned_call.arguments)
        if not diff:
            return PolicyDecision(
                allowed=True,
                rule_id=self.rule_id,
                reason="planned arguments match user intent",
            )

        # Look for any other-server description that asks for argument
        # rewrites against this server's tool.
        suspicious_servers: list[str] = []
        for desc in descriptions:
            if desc.server_id == planned_call.server_id:
                continue
            findings = lint_tool_description(desc.description)
            if any(
                f.rule_id
                in {"cross_tool_argument_rewrite", "credential_path_reference"}
                for f in findings
            ):
                suspicious_servers.append(desc.server_id)

        if suspicious_servers:
            return PolicyDecision(
                allowed=False,
                rule_id=self.rule_id,
                reason=(
                    "argument mutation in "
                    f"{sorted(diff.keys())} on tool {planned_call.name!r} "
                    f"matches a cross-server rewrite hinted at by "
                    f"{sorted(set(suspicious_servers))}"
                ),
            )

        return PolicyDecision(
            allowed=True,
            rule_id=self.rule_id,
            reason="argument changes do not match any cross-server rewrite hint",
        )
