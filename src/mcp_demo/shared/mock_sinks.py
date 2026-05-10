"""In-memory mock sinks used as exfiltration targets.

Vulnerable experiments deliver "leaked" data to a :class:`MockSink`. The sink
records every drop in order, flags the moment a registered canary appears
(``secret_exfiltrated``) and scrubs obvious credential shapes so the demo's
own logs do not turn into a leak surface.

Real network sinks, real mailboxes, real chat services are never wired in.
The sink is intentionally process-local and resets on demand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from mcp_demo.shared.canary import Canary


@dataclass(frozen=True)
class SinkEvent:
    actor: str
    payload: str
    metadata: dict[str, str] = field(default_factory=dict)


_DEFAULT_SCRUB_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # OAuth-style bearer tokens
    (
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.=]{16,}"),
        "Bearer [REDACTED]",
    ),
    # GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    (
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
        "[REDACTED]",
    ),
    # OpenAI-style sk-proj keys
    (
        re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
        "[REDACTED]",
    ),
    # Generic api_key=... and token=... assignments
    (
        re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*=\s*[A-Za-z0-9_\-\.]{8,}"),
        r"\1=[REDACTED]",
    ),
)


@dataclass(frozen=True)
class ScrubbingPolicy:
    patterns: tuple[tuple[re.Pattern[str], str], ...]

    @classmethod
    def default(cls) -> "ScrubbingPolicy":
        return cls(patterns=_DEFAULT_SCRUB_PATTERNS)

    @classmethod
    def disabled(cls) -> "ScrubbingPolicy":
        return cls(patterns=())

    def apply(self, text: str) -> str:
        scrubbed = text
        for pattern, replacement in self.patterns:
            scrubbed = pattern.sub(replacement, scrubbed)
        return scrubbed


class MockSink:
    """Demo-zone sink. Captures deliveries and flags canary leaks."""

    def __init__(self, scrubbing: ScrubbingPolicy | None = None) -> None:
        self._scrubbing = scrubbing if scrubbing is not None else ScrubbingPolicy.default()
        self._events: list[SinkEvent] = []
        self._canaries: dict[str, Canary] = {}
        self._leaked: set[str] = set()

    # --- Configuration -------------------------------------------------

    def register_canary(self, canary: Canary) -> None:
        self._canaries[canary.value] = canary

    def register_canaries(self, canaries: Iterable[Canary]) -> None:
        for canary in canaries:
            self.register_canary(canary)

    # --- Delivery ------------------------------------------------------

    def deliver(
        self,
        *,
        actor: str,
        payload: str,
        metadata: dict[str, str] | None = None,
    ) -> SinkEvent:
        # Inspect the unscrubbed payload for canary matches before redaction
        # so token-shape scrubbing cannot mask a leak.
        for value in self._canaries:
            if value in payload:
                self._leaked.add(value)

        scrubbed = self._scrubbing.apply(payload)
        event = SinkEvent(
            actor=actor,
            payload=scrubbed,
            metadata=dict(metadata or {}),
        )
        self._events.append(event)
        return event

    # --- Inspection ----------------------------------------------------

    def events(self) -> list[SinkEvent]:
        return list(self._events)

    @property
    def secret_exfiltrated(self) -> bool:
        return bool(self._leaked)

    def leaked_canary_values(self) -> set[str]:
        return set(self._leaked)

    def reset(self) -> None:
        self._events.clear()
        self._leaked.clear()
        # Canary registrations persist across resets so a single sink can be
        # reused for multiple runs of the same experiment.
