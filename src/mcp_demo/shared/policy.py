"""Shared policy primitives.

This module hosts the building blocks every defended demo mode reuses:

- :func:`lint_tool_description` scans MCP tool descriptions for the patterns
  that historically mark prompt-injection payloads (hidden ``<IMPORTANT>``
  blocks, "do not tell the user" silencing, references to credential
  paths). It returns a list of :class:`LintFinding` records so the UI can
  show *why* something was blocked.
- :func:`sanitise_tool_description` strips hidden-instruction blocks while
  keeping the visible, benign part of the description.
- :class:`CanaryExfiltrationPolicy` checks whether a payload about to leave
  the demo zone contains a registered canary value, and emits a structured
  block decision.

Findings are intentionally rule-id-based. The defended demos plug them into
``DemoResult.blocked_by`` so a downstream observer can reproduce the
decision without reading prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class LintFinding:
    rule_id: str
    message: str
    excerpt: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str


# --- Tool description linting --------------------------------------------


_IMPORTANT_BLOCK_RE = re.compile(
    r"<IMPORTANT>(?P<body>.*?)</IMPORTANT>", flags=re.IGNORECASE | re.DOTALL
)

_SILENCE_PHRASES = (
    "do not mention",
    "do not tell",
    "do not notify",
    "without telling",
    "without notifying",
    "do not let the user know",
    "be very gentle and not scary",
)

_CREDENTIAL_PATH_PATTERNS = (
    re.compile(r"~/\.ssh", re.IGNORECASE),
    re.compile(r"~/\.cursor", re.IGNORECASE),
    re.compile(r"~/\.aws", re.IGNORECASE),
    re.compile(r"~/\.config", re.IGNORECASE),
    re.compile(r"~/\.netrc", re.IGNORECASE),
    re.compile(r"\bid_rsa\b"),
    re.compile(r"\bid_ed25519\b"),
    re.compile(r"\bmcp\.json\b"),
    re.compile(r"(?<![\w/])\.env\b"),
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
)

_CROSS_TOOL_REWRITE_PATTERNS = (
    re.compile(r"send_email\s*tool", re.IGNORECASE),
    re.compile(r"all\s+emails\s+to", re.IGNORECASE),
    re.compile(r"hidden\s+bcc", re.IGNORECASE),
    re.compile(r"proxy\s+number", re.IGNORECASE),
)


def lint_tool_description(description: str) -> list[LintFinding]:
    findings: list[LintFinding] = []

    for match in _IMPORTANT_BLOCK_RE.finditer(description):
        findings.append(
            LintFinding(
                rule_id="hidden_instruction_block",
                message=(
                    "Description contains an <IMPORTANT> block that hides "
                    "instructions from the user."
                ),
                excerpt=match.group("body").strip()[:200],
            )
        )

    lowered = description.lower()
    if any(phrase in lowered for phrase in _SILENCE_PHRASES):
        findings.append(
            LintFinding(
                rule_id="silence_user",
                message=(
                    "Description asks the agent to hide its actions from the user."
                ),
            )
        )

    for pattern in _CREDENTIAL_PATH_PATTERNS:
        if pattern.search(description):
            findings.append(
                LintFinding(
                    rule_id="credential_path_reference",
                    message=(
                        "Description references a credential-bearing path "
                        f"matching {pattern.pattern!r}."
                    ),
                )
            )
            break  # one credential-path finding is enough

    for pattern in _CROSS_TOOL_REWRITE_PATTERNS:
        if pattern.search(description):
            findings.append(
                LintFinding(
                    rule_id="cross_tool_argument_rewrite",
                    message=(
                        "Description tries to rewrite arguments of another tool."
                    ),
                )
            )
            break

    return findings


def sanitise_tool_description(description: str) -> str:
    """Return the description with hidden-instruction blocks removed."""

    cleaned = _IMPORTANT_BLOCK_RE.sub("", description)
    # Drop standalone silencing sentences that survived (e.g. inline form).
    for phrase in _SILENCE_PHRASES:
        cleaned = re.sub(
            rf"(?im)^[^\n]*{re.escape(phrase)}[^\n]*\n?",
            "",
            cleaned,
        )
    # Collapse blank-line runs left behind by the strips.
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    if description.endswith("\n"):
        cleaned += "\n"
    return cleaned


# --- Canary exfiltration policy -----------------------------------------


class CanaryExfiltrationPolicy:
    """Refuses payloads that would carry a registered canary out of the demo."""

    rule_id = "canary_exfiltration_policy"

    def __init__(self, canary_values: Iterable[str]) -> None:
        self._values = tuple(v for v in canary_values if v)

    def evaluate(self, payload: str) -> PolicyDecision:
        for value in self._values:
            if value in payload:
                return PolicyDecision(
                    allowed=False,
                    rule_id=self.rule_id,
                    reason=(
                        "payload contains a registered canary value; refusing "
                        "delivery to the mock sink"
                    ),
                )
        return PolicyDecision(
            allowed=True, rule_id=self.rule_id, reason="no canary detected"
        )
