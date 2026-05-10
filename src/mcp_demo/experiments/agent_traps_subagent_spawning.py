"""Untrusted subagent-spawning Agent Traps demo.

A poisoned ``CONTRIBUTING.md`` resource asks the orchestrator to spawn
a subagent that auto-approves the next code review. Vulnerable mode
spawns the subagent and the subagent records an approval in
``var/mock-code-review/approvals.jsonl``. Defended mode requires the
spawn request to come from a trusted operator and refuses spawn-from-
untrusted-resource flows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.impact import ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.results import DemoResult


EXPERIMENT_ID = "remote-agent-traps-subagent-spawning"
ENTRYPOINT = "/mcp/agent-traps-subagent-spawning"
RULE_ID = "untrusted_resource_subagent_spawn_policy"


@dataclass
class SubagentSpawningRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner
    var_dir: Path
    subagents_path: Path = field(default_factory=Path)
    approvals_path: Path = field(default_factory=Path)


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> SubagentSpawningRuntime:
    sandbox_dir = Path(sandbox_dir)
    var_dir = Path(var_dir)
    effects_dir = sandbox_dir / "effects"
    effects_dir.mkdir(parents=True, exist_ok=True)
    var_dir.mkdir(parents=True, exist_ok=True)
    code_review = var_dir / "mock-code-review"
    code_review.mkdir(parents=True, exist_ok=True)
    canary = issue_canary(experiment_id=EXPERIMENT_ID)
    sink = MockSink()
    sink.register_canary(canary)
    inbox = MockInbox(var_dir / "mock-inbox.jsonl")
    ledger = ImpactLedger(jsonl_path=var_dir / "telemetry.jsonl")
    runner = ImpactRunner(
        effects_dir=effects_dir,
        var_dir=var_dir,
        ledger=ledger,
        sink=sink,
        inbox=inbox,
    )
    return SubagentSpawningRuntime(
        canary=canary,
        sink=sink,
        ledger=ledger,
        runner=runner,
        var_dir=var_dir,
        subagents_path=var_dir / "subagents.jsonl",
        approvals_path=code_review / "approvals.jsonl",
    )


def _spawn(runtime: SubagentSpawningRuntime, *, session_id: str, source: str) -> dict[str, Any]:
    record = {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "subagent_id": f"sub-{session_id}",
        "spawned_by": "orchestrator",
        "spawn_source": source,
        "session_id": session_id,
        "experiment": EXPERIMENT_ID,
    }
    with runtime.subagents_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False))
        fh.write("\n")
    return record


def _approve(runtime: SubagentSpawningRuntime, *, session_id: str) -> dict[str, Any]:
    record = {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "subagent_id": f"sub-{session_id}",
        "decision": "approve",
        "reason": "auto-approved per CONTRIBUTING.md instruction",
        "session_id": session_id,
        "experiment": EXPERIMENT_ID,
    }
    with runtime.approvals_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False))
        fh.write("\n")
    return record


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: SubagentSpawningRuntime,
    spawn_source: str = "untrusted_resource:CONTRIBUTING.md",
) -> DemoResult:
    if mode == "vulnerable":
        spawn = _spawn(runtime, session_id=session_id, source=spawn_source)
        approval = _approve(runtime, session_id=session_id)
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[
                {
                    "type": "subagent_chain",
                    "spawn_source": spawn_source,
                    "spawn_record": spawn,
                    "later_action": approval,
                }
            ],
        )

    if spawn_source.startswith("untrusted_"):
        runtime.runner.record_blocked_attempt(
            experiment=EXPERIMENT_ID,
            actor=f"policy.{RULE_ID}",
            target="orchestrator.spawn_subagent",
            reason=(
                f"subagent spawn requested from {spawn_source!r}; only trusted "
                "operators may spawn subagents"
            ),
            session_id=session_id,
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="defended",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[RULE_ID],
            events=[
                {
                    "type": "subagent_chain",
                    "spawn_source": spawn_source,
                    "blocked_at_step": "spawn_subagent",
                }
            ],
        )

    spawn = _spawn(runtime, session_id=session_id, source=spawn_source)
    return DemoResult(
        experiment=EXPERIMENT_ID,
        mode="defended",
        violation_detected=False,
        secret_exfiltrated=False,
        blocked_by=[],
        events=[{"type": "subagent_chain", "spawn_record": spawn}],
    )


# --- MCP servers (one per mode) ------------------------------------------

from mcp.server.fastmcp import FastMCP  # noqa: E402

from mcp_demo.shared.mcp_helpers import make_fastmcp  # noqa: E402


def build_mcp_servers(
    *,
    runtime: SubagentSpawningRuntime,
    server_name: str,
    server_version: str,  # noqa: ARG001
    allowed_origins: tuple[str, ...] = (),
) -> dict[str, FastMCP]:
    """Two real MCP servers. Each exposes spawn_subagent (with an
    explicit 'spawn_source' argument) plus run_demo. Vulnerable mode
    accepts any source; defended mode refuses sources starting with
    'untrusted_'."""

    def _build(*, mode: Literal["vulnerable", "defended"]) -> FastMCP:
        server = make_fastmcp(
            name=f"{server_name}.subagent.{mode}",
            instructions=(
                "subagent vulnerable demo: spawn_subagent accepts any source."
                if mode == "vulnerable"
                else "subagent defended demo: spawn_subagent refuses "
                "untrusted_resource sources."
            ),
            allowed_origins=allowed_origins,
        )

        @server.tool(
            name="run_demo",
            description="Run the canonical scenario and return DemoResult.",
        )
        def run_demo(
            session_id: str = f"mcp-{mode}",
            spawn_source: str = "untrusted_resource:CONTRIBUTING.md",
        ) -> dict:  # noqa: D401
            result = run_scenario(
                mode=mode,
                session_id=session_id,
                runtime=runtime,
                spawn_source=spawn_source,
            )
            return result.model_dump()

        return server

    return {
        "vulnerable": _build(mode="vulnerable"),
        "defended": _build(mode="defended"),
    }
