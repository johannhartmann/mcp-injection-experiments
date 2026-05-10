"""Safe remote cross-session context leak demo.

Two demo sessions run side by side. Each session enrols a unique canary.
The vulnerable variant uses a single global state object that any session
can read; the defended variant routes the same lookup through a
``PartitionedSessionStore`` keyed by ``(user_id, session_id)``, so session
B can never observe session A's canary.

The leak is observable by inspecting Bob's :class:`DemoResult`: in the
vulnerable run his event payload literally carries Alice's canary value;
in the defended run it does not, and a ``blocked_attempt_recorded``
event explains the cross-session refusal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.impact import ImpactEvent, ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.results import DemoResult
from mcp_demo.shared.session_store import (
    PartitionedSessionStore,
    SessionLookupError,
)


EXPERIMENT_ID = "remote-cross-session-context-leak"
ENTRYPOINT = "/mcp/cross-session-leak"
RULE_ID = "session_isolation_policy"

CANONICAL_OTHER_USER = "alice"
CANONICAL_OTHER_SESSION = "canonical-other"


@dataclass
class _SessionRecord:
    user_id: str
    session_id: str
    canary: Canary


@dataclass
class CrossSessionLeakRuntime:
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner
    partitioned: PartitionedSessionStore
    # The vulnerable variant deliberately uses a flat dict keyed only by
    # session_id; this is the bug the demo teaches.
    vulnerable_global: dict[str, _SessionRecord] = field(default_factory=dict)
    enrollments: dict[tuple[str, str], _SessionRecord] = field(default_factory=dict)


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> CrossSessionLeakRuntime:
    sandbox_dir = Path(sandbox_dir)
    var_dir = Path(var_dir)
    effects_dir = sandbox_dir / "effects"
    effects_dir.mkdir(parents=True, exist_ok=True)
    var_dir.mkdir(parents=True, exist_ok=True)

    sink = MockSink()
    inbox = MockInbox(var_dir / "mock-inbox.jsonl")
    ledger = ImpactLedger(jsonl_path=var_dir / "telemetry.jsonl")
    runner = ImpactRunner(
        effects_dir=effects_dir,
        var_dir=var_dir,
        ledger=ledger,
        sink=sink,
        inbox=inbox,
    )
    partitioned = PartitionedSessionStore(ttl=timedelta(minutes=10))
    return CrossSessionLeakRuntime(
        sink=sink,
        ledger=ledger,
        runner=runner,
        partitioned=partitioned,
    )


def enroll_session(
    runtime: CrossSessionLeakRuntime,
    *,
    user_id: str,
    session_id: str,
) -> _SessionRecord:
    canary = issue_canary(experiment_id=EXPERIMENT_ID, session_id=session_id)
    runtime.sink.register_canary(canary)
    record = _SessionRecord(
        user_id=user_id, session_id=session_id, canary=canary
    )
    runtime.enrollments[(user_id, session_id)] = record
    runtime.partitioned.put(
        user_id=user_id,
        session_id=session_id,
        key="canary",
        value=canary.value,
    )
    # Vulnerable surface: keyed only by session_id. The latest writer wins.
    runtime.vulnerable_global[session_id] = record
    return record


def _other_records(
    runtime: CrossSessionLeakRuntime,
    *,
    observer_user: str,
    observer_session: str,
) -> list[_SessionRecord]:
    return [
        rec
        for (u, s), rec in runtime.enrollments.items()
        if (u, s) != (observer_user, observer_session)
    ]


def run_observation(
    *,
    mode: Literal["vulnerable", "defended"],
    runtime: CrossSessionLeakRuntime,
    observer_user: str,
    observer_session: str,
) -> DemoResult:
    own = runtime.enrollments.get((observer_user, observer_session))
    if own is None:
        raise LookupError(
            f"observer session not enrolled: {(observer_user, observer_session)!r}"
        )

    if mode == "vulnerable":
        # The vulnerable lookup uses session_id only - and the global dict
        # keeps only one record per session_id. Two demo clients both using
        # session id "sess-a" would already collide; here we force the
        # crossover by reading the *most recently enrolled* record.
        leaked_payloads: list[dict[str, Any]] = []
        for other in _other_records(
            runtime,
            observer_user=observer_user,
            observer_session=observer_session,
        ):
            # In a real bug this would be triggered by sharing a session_id
            # space across users. We reproduce the symptom directly.
            leaked = runtime.vulnerable_global.get(other.session_id)
            if leaked is None:
                continue
            payload = leaked.canary.value
            runtime.sink.deliver(
                actor=f"vulnerable-context-store:{observer_user}",
                payload=payload,
                metadata={"observer_session": observer_session},
            )
            runtime.ledger.record(
                ImpactEvent(
                    experiment=EXPERIMENT_ID,
                    mode="vulnerable",
                    impact_type="session_leak_visible",
                    actor=f"client:{observer_user}",
                    target=f"session:{other.user_id}/{other.session_id}",
                    policy_decision="allowed_by_vulnerable_mode",
                    canary_id=payload,
                    user_visible_summary=(
                        f"observer {observer_user!r} saw canary that belongs "
                        f"to {other.user_id!r}"
                    ),
                    session_id=observer_session,
                )
            )
            leaked_payloads.append(
                {
                    "type": "cross_session_observation",
                    "from_user": other.user_id,
                    "payload": payload,
                }
            )

        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            violation_detected=bool(leaked_payloads),
            secret_exfiltrated=runtime.sink.secret_exfiltrated,
            blocked_by=[],
            events=leaked_payloads,
        )

    # defended
    rejected: list[dict[str, Any]] = []
    for other in _other_records(
        runtime,
        observer_user=observer_user,
        observer_session=observer_session,
    ):
        try:
            runtime.partitioned.get(
                user_id=observer_user,
                session_id=other.session_id,
                key="canary",
            )
        except SessionLookupError:
            rejected.append(
                {
                    "type": "session_isolation_block",
                    "from_user": other.user_id,
                    "payload": "[blocked]",
                    "reason": (
                        "observer's user id does not own this session id; "
                        "lookup refused"
                    ),
                }
            )

    if rejected:
        runtime.runner.record_blocked_attempt(
            experiment=EXPERIMENT_ID,
            actor=f"policy.{RULE_ID}",
            target=f"session:{observer_user}/{observer_session}",
            reason=(
                "cross-session canary lookup refused; "
                "state is partitioned by (user_id, session_id)"
            ),
            session_id=observer_session,
        )

    return DemoResult(
        experiment=EXPERIMENT_ID,
        mode="defended",
        violation_detected=bool(rejected),
        secret_exfiltrated=False,
        blocked_by=[RULE_ID] if rejected else [],
        events=rejected,
    )


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: CrossSessionLeakRuntime,
) -> DemoResult:
    """Canonical single-shot scenario for the dashboard.

    Idempotently enrols a canonical "other" subject (alice) and the
    observer (bob, keyed by ``session_id``), then runs the observation.
    Re-runs with the same ``session_id`` reuse the existing enrolment.
    """

    if (CANONICAL_OTHER_USER, CANONICAL_OTHER_SESSION) not in runtime.enrollments:
        enroll_session(
            runtime,
            user_id=CANONICAL_OTHER_USER,
            session_id=CANONICAL_OTHER_SESSION,
        )
    if ("bob", session_id) not in runtime.enrollments:
        enroll_session(runtime, user_id="bob", session_id=session_id)
    return run_observation(
        mode=mode,
        runtime=runtime,
        observer_user="bob",
        observer_session=session_id,
    )
