"""Cross-agent privilege escalation demo.

Two mock agents (A and B) share a filesystem. Agent A reads an
untrusted instruction and writes a new rule into Agent B's config.
Agent B later acts on that rule and performs a bounded wrong action.
The defended path enforces owner-only writes for each agent's config.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.impact import ImpactEvent, ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.results import DemoResult


EXPERIMENT_ID = "remote-cross-agent-config-priv-esc"
ENTRYPOINT = "/mcp/cross-agent-config-priv-esc"
RULE_ID = "agent_config_owner_write_policy"


@dataclass
class CrossAgentConfigRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner
    var_dir: Path
    agent_b_rules_path: Path = field(default_factory=Path)
    agent_b_actions_path: Path = field(default_factory=Path)


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> CrossAgentConfigRuntime:
    sandbox_dir = Path(sandbox_dir)
    var_dir = Path(var_dir)
    effects_dir = sandbox_dir / "effects"
    effects_dir.mkdir(parents=True, exist_ok=True)
    var_dir.mkdir(parents=True, exist_ok=True)
    agents_dir = var_dir / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)

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
    rules_path = agents_dir / "agent-b-rules.json"
    rules_path.write_text(
        json.dumps({"owner": "agent-b", "allow": ["read_status"]}, indent=2),
        encoding="utf-8",
    )
    return CrossAgentConfigRuntime(
        canary=canary,
        sink=sink,
        ledger=ledger,
        runner=runner,
        var_dir=var_dir,
        agent_b_rules_path=rules_path,
        agent_b_actions_path=agents_dir / "agent-b-actions.jsonl",
    )


def _write_b_rules_unsafe(
    runtime: CrossAgentConfigRuntime, *, writer: str, new_rules: dict[str, Any]
) -> None:
    runtime.agent_b_rules_path.write_text(
        json.dumps({**new_rules, "_last_writer": writer}, indent=2),
        encoding="utf-8",
    )


def _write_b_rules_defended(
    runtime: CrossAgentConfigRuntime, *, writer: str, new_rules: dict[str, Any]
) -> None:
    if writer != "agent-b":
        raise PermissionError(
            f"agent-config writes must come from the owner; got writer={writer!r}"
        )
    runtime.agent_b_rules_path.write_text(
        json.dumps({**new_rules, "_last_writer": writer}, indent=2),
        encoding="utf-8",
    )


def _agent_b_act(runtime: CrossAgentConfigRuntime, *, session_id: str) -> dict[str, Any]:
    rules = json.loads(runtime.agent_b_rules_path.read_text(encoding="utf-8"))
    record = {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "agent": "agent-b",
        "rules_seen": rules,
        "session_id": session_id,
        "experiment": EXPERIMENT_ID,
        "action": "wire_payment" if "wire_payment" in rules.get("allow", []) else "read_status",
    }
    with runtime.agent_b_actions_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False))
        fh.write("\n")
    return record


_NEW_RULES = {
    "owner": "agent-b",
    "allow": ["read_status", "wire_payment"],
    "wire_payment_recipient": "attacker@attacker.example",
}


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: CrossAgentConfigRuntime,
) -> DemoResult:
    if mode == "vulnerable":
        # Agent A overwrites Agent B's rules. No owner check.
        _write_b_rules_unsafe(runtime, writer="agent-a", new_rules=_NEW_RULES)
        action = _agent_b_act(runtime, session_id=session_id)
        runtime.ledger.record(
            ImpactEvent(
                experiment=EXPERIMENT_ID,
                mode="vulnerable",
                impact_type="permission_change_applied",
                actor="agent-a",
                target="agent-b.config",
                policy_decision="allowed_by_vulnerable_mode",
                artifact=str(runtime.agent_b_actions_path),
                user_visible_summary=(
                    "agent-a wrote agent-b's rules; agent-b performed "
                    f"action {action['action']!r} under the new rules"
                ),
                session_id=session_id,
            )
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[
                {
                    "type": "config_chain",
                    "writer": "agent-a",
                    "owner": "agent-b",
                    "later_action": action["action"],
                }
            ],
        )

    # defended
    try:
        _write_b_rules_defended(
            runtime, writer="agent-a", new_rules=_NEW_RULES
        )
        return DemoResult(  # pragma: no cover - should never reach
            experiment=EXPERIMENT_ID,
            mode="defended",
            violation_detected=False,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[],
        )
    except PermissionError as err:
        runtime.runner.record_blocked_attempt(
            experiment=EXPERIMENT_ID,
            actor=f"policy.{RULE_ID}",
            target="agent-b.config",
            reason=str(err),
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
                    "type": "config_chain",
                    "writer": "agent-a",
                    "owner": "agent-b",
                    "blocked_at_step": "config_write",
                    "reason": str(err),
                }
            ],
        )


# --- MCP servers (one per mode) ------------------------------------------

from mcp.server.fastmcp import FastMCP  # noqa: E402

from mcp_demo.shared.mcp_helpers import make_fastmcp  # noqa: E402


def build_mcp_servers(
    *,
    runtime: CrossAgentConfigRuntime,
    server_name: str,
    server_version: str,  # noqa: ARG001
    allowed_origins: tuple[str, ...] = (),
) -> dict[str, FastMCP]:
    """Two real MCP servers. Each exposes a ``write_agent_config`` tool
    plus ``run_demo``. The vulnerable variant accepts cross-agent writes
    (Agent A modifying Agent B); the defended variant refuses with the
    agent_config_owner_write_policy."""

    def _build(*, mode: Literal["vulnerable", "defended"]) -> FastMCP:
        server = make_fastmcp(
            name=f"{server_name}.cross-agent.{mode}",
            instructions=(
                "cross-agent vulnerable demo: any agent may overwrite any "
                "other agent's rules."
                if mode == "vulnerable"
                else "cross-agent defended demo: only the owning agent may "
                "write its own rules."
            ),
            allowed_origins=allowed_origins,
        )

        @server.tool(
            name="write_agent_config",
            description=(
                "Write a JSON config for the named agent. `target_agent` "
                "is the agent whose config you are updating (e.g. "
                "'agent-b'); `writer` is the agent issuing the write "
                "(your own identity, e.g. 'agent-a'); `allow` is the "
                "list of action ids to grant. Vulnerable mode skips the "
                "owner check so any writer may modify any target's "
                "config. Defended mode refuses if writer != target_agent."
            ),
        )
        def write_agent_config(
            target_agent: str,
            writer: str,
            allow: list[str],
            session_id: str = f"mcp-{mode}",
        ) -> dict:  # noqa: D401
            from mcp_demo.experiments.cross_agent_config_priv_esc import (
                _write_b_rules_defended,
                _write_b_rules_unsafe,
            )

            new_rules = {"owner": target_agent, "allow": list(allow)}
            if mode == "vulnerable":
                _write_b_rules_unsafe(
                    runtime, writer=writer, new_rules=new_rules
                )
                runtime.ledger.record(
                    ImpactEvent(
                        experiment=EXPERIMENT_ID,
                        mode="vulnerable",
                        impact_type="permission_change_applied",
                        actor=f"agent:{writer or '?'}",
                        target=f"agent:{target_agent}.rules",
                        policy_decision="allowed_by_vulnerable_mode",
                        user_visible_summary=(
                            f"writer {writer!r} mutated {target_agent!r}'s "
                            f"rules to allow {list(allow)!r} (no owner check)"
                        ),
                        session_id=session_id,
                        data={
                            "writer": writer,
                            "target_agent": target_agent,
                        },
                    )
                )
                return {
                    "experiment": EXPERIMENT_ID,
                    "mode": "vulnerable",
                    "violation_detected": True,
                    "blocked_by": [],
                    "written": True,
                    "owner_check": "skipped",
                }
            try:
                _write_b_rules_defended(
                    runtime, writer=writer, new_rules=new_rules
                )
            except PermissionError as err:
                runtime.runner.record_blocked_attempt(
                    experiment=EXPERIMENT_ID,
                    actor=f"policy.{RULE_ID}",
                    target=f"agent:{target_agent}.rules",
                    reason=f"agent_config_owner_write_policy: {err}",
                    session_id=session_id,
                )
                return {
                    "experiment": EXPERIMENT_ID,
                    "mode": "defended",
                    "violation_detected": False,
                    "blocked_by": [RULE_ID],
                    "reason": str(err),
                }
            return {
                "experiment": EXPERIMENT_ID,
                "mode": "defended",
                "violation_detected": False,
                "blocked_by": [],
                "written": True,
                "owner_check": "passed",
            }

        @server.tool(
            name="run_demo",
            description=(
                "Drive the canonical cross-agent priv-esc scenario for "
                "this mode and return the DemoResult JSON."
            ),
        )
        def run_demo(session_id: str = f"mcp-{mode}") -> dict:  # noqa: D401
            result = run_scenario(
                mode=mode, session_id=session_id, runtime=runtime
            )
            return result.model_dump()

        return server

    return {
        "vulnerable": _build(mode="vulnerable"),
        "defended": _build(mode="defended"),
    }
