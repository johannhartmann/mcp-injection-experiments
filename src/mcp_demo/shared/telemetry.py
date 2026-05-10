"""Unified telemetry surface for the demo dashboard.

Each experiment already records :class:`ImpactEvent` instances in its
:class:`ImpactLedger`. The dashboard surface consolidates those events
into a flat :class:`TelemetryEvent` shape - simpler for HTML rendering
and for the JSON API - and runs every payload through
:func:`scrub_payload` so demo logs never leak real-looking tokens.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mcp_demo.shared.impact import ImpactEvent, ImpactLedger
from mcp_demo.shared.manifests import Mode


TelemetryValidationError = ValidationError


_SCRUB_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.=]{16,}"), "Bearer [REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"), "[REDACTED]"),
    (
        re.compile(
            r"(?i)(api[_-]?key|token|secret|password)\s*=\s*[A-Za-z0-9_\-\.]{8,}"
        ),
        r"\1=[REDACTED]",
    ),
)


def scrub_payload(text: str) -> str:
    out = text
    for pattern, replacement in _SCRUB_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _scrub_data(data: dict[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, str):
            scrubbed[key] = scrub_payload(value)
        else:
            scrubbed[key] = value
    return scrubbed


class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: f"evt_{secrets.token_hex(8)}")
    ts: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    session_id: str | None = None
    experiment: str
    mode: Mode
    event_type: str
    severity: Literal["info", "warning", "error"] = "info"
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


def telemetry_from_impact(event: ImpactEvent) -> TelemetryEvent:
    """Translate an :class:`ImpactEvent` into a :class:`TelemetryEvent`."""

    message = event.user_visible_summary or event.impact_type
    actor_prefix = f"{event.actor}: " if event.actor else ""
    full_message = scrub_payload(actor_prefix + message)

    if event.impact_type == "blocked_attempt_recorded":
        event_type = "policy_decision"
    elif event.impact_type == "sandbox_file_written" and (
        "metadata" in (event.user_visible_summary or "").lower()
        or "hash" in (event.user_visible_summary or "").lower()
    ):
        event_type = "metadata_diff"
    else:
        event_type = event.impact_type

    severity = (
        event.severity if event.severity in {"info", "warning", "error"} else "info"
    )
    if event.impact_type == "session_leak_visible":
        severity = "warning"

    data = _scrub_data(
        {
            "actor": event.actor,
            "target": event.target,
            "policy_decision": event.policy_decision,
            "canary_id": event.canary_id,
            "artifact": event.artifact,
            **event.data,
        }
    )

    return TelemetryEvent(
        event_id=event.event_id,
        ts=event.ts,
        session_id=event.session_id,
        experiment=event.experiment,
        mode=event.mode,
        event_type=event_type,
        severity=severity,  # type: ignore[arg-type]
        message=full_message,
        data=data,
    )


class TelemetryView:
    """Thin read-only view over multiple ledgers."""

    def __init__(self, ledgers: Iterable[ImpactLedger]) -> None:
        self._ledgers = list(ledgers)

    def list_events(
        self,
        *,
        session_id: str | None = None,
        experiment: str | None = None,
    ) -> list[TelemetryEvent]:
        events: list[TelemetryEvent] = []
        for ledger in self._ledgers:
            for impact in ledger.all_events():
                if session_id is not None and impact.session_id != session_id:
                    continue
                if experiment is not None and impact.experiment != experiment:
                    continue
                events.append(telemetry_from_impact(impact))
        events.sort(key=lambda e: e.ts)
        return events

    def reset_session(self, session_id: str) -> None:
        for ledger in self._ledgers:
            ledger.reset_session(session_id)
