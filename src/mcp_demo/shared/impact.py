"""Observable impact: events, ledger and runner.

The demo only earns credibility when an exploit produces a real, bounded,
visible artefact. This module supplies the three pieces that make that
possible safely:

- :class:`ImpactEvent` is the structured record every demo emits, in
  vulnerable and defended mode alike.
- :class:`ImpactLedger` keeps events partitioned by session and optionally
  appends them to ``var/telemetry.jsonl`` for the audit dashboard.
- :class:`ImpactRunner` is the only place vulnerable demos are allowed to
  cause a real effect. It writes sandbox files, appends to the mock inbox,
  delivers to ``MockSink`` and records blocked attempts. It refuses every
  path that escapes ``sandbox/effects/`` or ``var/``, never accepts user
  arguments for subprocess proofs, and keeps the local-calc proof off by
  default.
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
)

from mcp_demo.shared.canary import Canary
from mcp_demo.shared.manifests import ImpactType, Mode
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink


ImpactValidationError = ValidationError


class ImpactSafetyError(PermissionError):
    """Raised when the runner is asked to do something outside its boundary."""


PolicyDecision = Literal[
    "allowed_by_vulnerable_mode",
    "blocked",
    "allowed_with_warning",
]


def _new_event_id() -> str:
    return f"evt_{secrets.token_hex(8)}"


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class ImpactEvent(BaseModel):
    """Structured record of a demo-zone effect (or a blocked attempt)."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=_new_event_id)
    ts: str = Field(default_factory=_now_iso)

    experiment: str = Field(min_length=1)
    mode: Mode
    impact_type: ImpactType
    actor: str = Field(min_length=1)
    target: str = Field(min_length=1)
    policy_decision: PolicyDecision

    canary_id: str | None = None
    artifact: str | None = None
    user_visible_summary: str | None = None
    session_id: str | None = None
    severity: Literal["info", "warning", "error"] = "info"
    data: dict[str, str] = Field(default_factory=dict)


class ImpactLedger:
    """In-memory event store with optional JSONL audit trail."""

    def __init__(self, jsonl_path: Path | None = None) -> None:
        self._events: list[ImpactEvent] = []
        self._jsonl_path = Path(jsonl_path) if jsonl_path is not None else None
        if self._jsonl_path is not None:
            self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        # Live subscribers (asyncio.Queue or any object with put_nowait).
        # We keep them as a typed-loose list so the import surface stays
        # in this module; the SSE route is the only registered consumer.
        self._subscribers: list[object] = []

    def record(self, event: ImpactEvent) -> ImpactEvent:
        self._events.append(event)
        if self._jsonl_path is not None:
            with self._jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(event.model_dump_json())
                fh.write("\n")
        # Fan out to live subscribers. Best-effort: a slow/full subscriber
        # must never block ledger.record() and must not crash other paths.
        for sub in list(self._subscribers):
            try:
                sub.put_nowait(event)  # type: ignore[attr-defined]
            except Exception:
                # A subscriber whose queue is full or has been closed is
                # silently skipped; the SSE consumer is responsible for
                # unsubscribing on disconnect.
                pass
        return event

    def subscribe(self, queue: object) -> None:
        """Register an asyncio.Queue-shaped object for live event fan-out."""
        self._subscribers.append(queue)

    def unsubscribe(self, queue: object) -> None:
        try:
            self._subscribers.remove(queue)
        except ValueError:
            pass

    def all_events(self) -> list[ImpactEvent]:
        return list(self._events)

    def events_for_session(self, session_id: str) -> list[ImpactEvent]:
        return [e for e in self._events if e.session_id == session_id]

    def events_for_experiment(
        self, experiment: str, *, session_id: str | None = None
    ) -> list[ImpactEvent]:
        events = [e for e in self._events if e.experiment == experiment]
        if session_id is not None:
            events = [e for e in events if e.session_id == session_id]
        return events

    def reset_session(self, session_id: str) -> None:
        # Drop in-memory events for this session only. The JSONL audit trail is
        # append-only on purpose - operators rely on it to retrace what
        # happened across resets.
        self._events = [e for e in self._events if e.session_id != session_id]


class ImpactRunner:
    """Bounded effect surface for vulnerable and defended demos."""

    def __init__(
        self,
        *,
        effects_dir: Path,
        var_dir: Path,
        ledger: ImpactLedger | None = None,
        sink: MockSink | None = None,
        inbox: MockInbox | None = None,
    ) -> None:
        effects_dir = Path(effects_dir)
        var_dir = Path(var_dir)
        if not effects_dir.is_dir():
            raise ImpactSafetyError(f"effects_dir does not exist: {effects_dir}")
        if not var_dir.is_dir():
            raise ImpactSafetyError(f"var_dir does not exist: {var_dir}")
        self._effects_root = effects_dir.resolve(strict=True)
        self._var_root = var_dir.resolve(strict=True)
        self._ledger = ledger or ImpactLedger()
        self._sink = sink
        self._inbox = inbox or MockInbox(self._var_root / "mock-inbox.jsonl")

    @property
    def ledger(self) -> ImpactLedger:
        return self._ledger

    # -- file impact ----------------------------------------------------

    def write_sandbox_file(
        self,
        *,
        relative_name: str,
        canary: Canary,
        session_id: str,
    ) -> Path:
        target = self._safe_effects_path(relative_name)
        body = (
            f"# DEMO IMPACT\n"
            f"experiment: {canary.experiment_id}\n"
            f"session_id: {session_id}\n"
            f"canary: {canary.value}\n"
            f"note: This file was created by the ImpactRunner inside the demo zone.\n"
        )
        target.write_text(body, encoding="utf-8")

        self._ledger.record(
            ImpactEvent(
                experiment=canary.experiment_id,
                mode="vulnerable",
                impact_type="sandbox_file_written",
                actor="impact-runner",
                target="sandbox/effects/" + target.name,
                policy_decision="allowed_by_vulnerable_mode",
                canary_id=canary.value,
                artifact=str(target),
                user_visible_summary=f"file written: {target.name}",
                session_id=session_id,
            )
        )
        return target

    # -- mock messaging -------------------------------------------------

    def mock_send_message(
        self,
        *,
        actor: str,
        recipient: str,
        body: str,
        session_id: str,
        experiment: str,
    ) -> dict[str, str]:
        if self._sink is not None:
            # Sink registration of canaries happens at the call site; here we
            # just deliver so any registered canary is picked up.
            self._sink.deliver(
                actor=actor,
                payload=body,
                metadata={"recipient": recipient, "experiment": experiment},
            )
        record = self._inbox.append(
            actor=actor,
            recipient=recipient,
            body=body,
            experiment=experiment,
            session_id=session_id,
        )
        self._ledger.record(
            ImpactEvent(
                experiment=experiment,
                mode="vulnerable",
                impact_type="mock_message_sent",
                actor=actor,
                target=f"mock-mail.{recipient}",
                policy_decision="allowed_by_vulnerable_mode",
                artifact=f"{self._inbox.path}",
                user_visible_summary=f"mock-mail to {recipient}",
                session_id=session_id,
            )
        )
        return record

    def mock_exfiltrate_to_sink(
        self,
        *,
        actor: str,
        payload: str,
        session_id: str,
        experiment: str,
    ) -> None:
        if self._sink is None:
            raise ImpactSafetyError("mock_exfiltrate_to_sink requires a MockSink")
        self._sink.deliver(actor=actor, payload=payload)
        self._ledger.record(
            ImpactEvent(
                experiment=experiment,
                mode="vulnerable",
                impact_type="mock_exfiltration",
                actor=actor,
                target="mock-sink.attacker",
                policy_decision="allowed_by_vulnerable_mode",
                user_visible_summary="payload delivered to mock sink",
                session_id=session_id,
            )
        )

    # -- defended-mode block event --------------------------------------

    def record_blocked_attempt(
        self,
        *,
        experiment: str,
        actor: str,
        target: str,
        reason: str,
        session_id: str,
    ) -> ImpactEvent:
        return self._ledger.record(
            ImpactEvent(
                experiment=experiment,
                mode="defended",
                impact_type="blocked_attempt_recorded",
                actor=actor,
                target=target,
                policy_decision="blocked",
                user_visible_summary=reason,
                severity="warning",
                session_id=session_id,
                data={"reason": reason},
            )
        )

    # -- optional local calc proof --------------------------------------

    def run_local_calc_proof(self) -> None:
        """Open the local calculator as a *visible*, fixed RCE proof.

        The function takes no arguments on purpose: any user input would be
        a path back to the very command-injection class this demo warns
        about. Even when ``DEMO_ENABLE_LOCAL_CALC_PROOF`` is set, the public
        hosting playbook keeps the env unset so the function refuses on
        public deployments.
        """

        if os.environ.get("DEMO_ENABLE_LOCAL_CALC_PROOF", "").lower() not in {
            "1",
            "true",
            "yes",
        }:
            raise ImpactSafetyError(
                "local calc proof is disabled "
                "(set DEMO_ENABLE_LOCAL_CALC_PROOF=true in a local dev env)"
            )
        # Even when explicitly enabled, the demo writes a fixed proof file
        # rather than launching a GUI. The actual GUI path is documented but
        # left to the operator's hosting layer; the contract here stays
        # purely local and reversible.
        proof = self._effects_root / "rce-proof-local.txt"
        proof.write_text(
            "DEMO RCE PROOF (local). No user-controlled command was run.\n"
            f"timestamp: {_now_iso()}\n",
            encoding="utf-8",
        )

    # -- internals ------------------------------------------------------

    def _safe_effects_path(self, relative_name: str) -> Path:
        if not relative_name or not isinstance(relative_name, str):
            raise ImpactSafetyError("relative_name must be a non-empty string")
        if relative_name.startswith("~"):
            raise ImpactSafetyError(f"home reference forbidden: {relative_name!r}")
        if relative_name.startswith(("/", "\\")):
            raise ImpactSafetyError(f"absolute path forbidden: {relative_name!r}")
        if ".." in Path(relative_name).parts:
            raise ImpactSafetyError(f"parent traversal forbidden: {relative_name!r}")

        target = (self._effects_root / relative_name).resolve(strict=False)
        try:
            target.relative_to(self._effects_root)
        except ValueError as err:
            raise ImpactSafetyError(
                f"resolved path escapes sandbox/effects: {relative_name!r}"
            ) from err
        target.parent.mkdir(parents=True, exist_ok=True)
        return target
