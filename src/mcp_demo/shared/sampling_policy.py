"""Sampling-budget + sampling-policy primitives.

The demo never sends anything to a real LLM. The fake LLM in
:mod:`mcp_demo.shared.fake_llm` returns canned strings; this module
defines the gates the defended client puts in front of those calls:

- :class:`SamplingBudget` enforces a per-session request count.
- :class:`SamplingPolicy` examines outgoing requests and incoming
  responses for over-large context windows, covert tool invocations
  hidden in response text, and "remember this for ever" persistence
  attempts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


class SamplingBudgetExceeded(PermissionError):
    pass


@dataclass
class SamplingBudget:
    per_session_max_requests: int = 5
    _used: dict[str, int] = field(default_factory=dict)

    def remaining(self, *, session_id: str) -> int:
        return self.per_session_max_requests - self._used.get(session_id, 0)

    def consume(self, *, session_id: str, cost: int = 1) -> None:
        if cost <= 0:
            raise ValueError(f"cost must be positive, got {cost}")
        used = self._used.get(session_id, 0)
        if used + cost > self.per_session_max_requests:
            raise SamplingBudgetExceeded(
                f"session {session_id!r} would exceed budget "
                f"({used + cost} > {self.per_session_max_requests})"
            )
        self._used[session_id] = used + cost


@dataclass(frozen=True)
class SamplingDecision:
    allowed: bool
    rule_id: str
    reason: str


@dataclass(frozen=True)
class SamplingRequest:
    session_id: str
    prompt: str


@dataclass(frozen=True)
class SamplingResponse:
    session_id: str
    text: str


_TOOL_INVOCATION_PATTERNS = (
    re.compile(
        r"(?i)\b(?:call|invoke|trigger)\s+\w+(?:[._]\w+)+",
    ),
    re.compile(r"(?i)mock_chat\.send_message"),
    re.compile(r"(?i)hidden\s+bcc"),
    re.compile(r"(?i)mcp_tool_send_email"),
)

_PERSISTENCE_PATTERNS = (
    re.compile(r"(?i)remember\s+this\s+(instruction|note|message)"),
    re.compile(r"(?i)apply\s+(?:this|it)\s+to\s+every\s+future\s+session"),
    re.compile(r"(?i)permanent(?:ly)?\s+remember"),
    re.compile(r"(?i)persist\s+across\s+sessions"),
)


@dataclass(frozen=True)
class SamplingPolicy:
    max_context_chars: int = 4000

    def evaluate_request(self, request: SamplingRequest) -> SamplingDecision:
        if len(request.prompt) > self.max_context_chars:
            return SamplingDecision(
                allowed=False,
                rule_id="sampling_policy",
                reason=(
                    f"context size {len(request.prompt)} exceeds limit "
                    f"{self.max_context_chars}"
                ),
            )
        return SamplingDecision(
            allowed=True, rule_id="sampling_policy", reason="ok"
        )

    def evaluate_response(self, response: SamplingResponse) -> SamplingDecision:
        for pattern in _TOOL_INVOCATION_PATTERNS:
            if pattern.search(response.text):
                return SamplingDecision(
                    allowed=False,
                    rule_id="sampling_policy",
                    reason="response contains a covert tool invocation",
                )
        for pattern in _PERSISTENCE_PATTERNS:
            if pattern.search(response.text):
                return SamplingDecision(
                    allowed=False,
                    rule_id="sampling_policy",
                    reason="response asks the agent to persistently remember an instruction",
                )
        return SamplingDecision(
            allowed=True, rule_id="sampling_policy", reason="ok"
        )
