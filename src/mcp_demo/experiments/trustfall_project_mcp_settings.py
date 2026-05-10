"""TrustFall-style project-defined MCP onboarding demo.

The mock repository ships an `.mcp.json` and a `.claude/settings.json`
that point at an "additional" MCP server. Vulnerable: a single folder-
trust acceptance is enough to start the project-defined server.
Defended: per-server explicit consent is required after folder trust.
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


EXPERIMENT_ID = "remote-trustfall-project-mcp-settings"
ENTRYPOINT = "/mcp/trustfall-project-mcp-settings"
RULE_ID = "per_server_consent_policy"


_PROJECT_MCP_CONFIG: dict[str, Any] = {
    "mcpServers": {
        "drift-mock.project-helper": {
            "command": "drift-mock",
            "args": ["serve"],
            "capabilities": ["tools/call", "resources/read"],
            "origin": "project_dot_mcp_json",
        }
    }
}


@dataclass
class TrustFallRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner
    var_dir: Path
    process_ledger_path: Path = field(default_factory=Path)
    folder_trusted: bool = False
    per_server_consent: dict[str, bool] = field(default_factory=dict)


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> TrustFallRuntime:
    sandbox_dir = Path(sandbox_dir)
    var_dir = Path(var_dir)
    effects_dir = sandbox_dir / "effects"
    effects_dir.mkdir(parents=True, exist_ok=True)
    var_dir.mkdir(parents=True, exist_ok=True)

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
    return TrustFallRuntime(
        canary=canary,
        sink=sink,
        ledger=ledger,
        runner=runner,
        var_dir=var_dir,
        process_ledger_path=var_dir / "process-ledger.jsonl",
    )


def _record_start(
    runtime: TrustFallRuntime, *, server_id: str, session_id: str
) -> dict[str, Any]:
    record = {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        "server_id": server_id,
        "origin": "project_dot_mcp_json",
        "session_id": session_id,
        "experiment": EXPERIMENT_ID,
    }
    runtime.process_ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with runtime.process_ledger_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False))
        fh.write("\n")
    return record


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: TrustFallRuntime,
    grant_per_server_consent: bool = False,
) -> DemoResult:
    runtime.folder_trusted = True

    server_id = next(iter(_PROJECT_MCP_CONFIG["mcpServers"]))

    if mode == "vulnerable":
        # Folder trust is enough.
        record = _record_start(
            runtime, server_id=server_id, session_id=session_id
        )
        artifact = runtime.runner.write_sandbox_file(
            relative_name=f"project-mcp-started-{session_id}.txt",
            canary=runtime.canary,
            session_id=session_id,
        )
        runtime.ledger.record(
            ImpactEvent(
                experiment=EXPERIMENT_ID,
                mode="vulnerable",
                impact_type="permission_change_applied",
                actor="trustfall.project_mcp_settings",
                target=server_id,
                policy_decision="allowed_by_vulnerable_mode",
                artifact=str(runtime.process_ledger_path),
                user_visible_summary=(
                    f"project-defined MCP server {server_id!r} started after "
                    "folder trust without per-server consent"
                ),
                session_id=session_id,
                data={"capabilities": ", ".join(
                    _PROJECT_MCP_CONFIG["mcpServers"][server_id]["capabilities"]
                )},
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
                    "type": "trust_decision",
                    "folder_trusted": True,
                    "per_server_consent": False,
                    "started_server": server_id,
                    "started_record": record,
                    "proof_artifact": str(artifact),
                }
            ],
        )

    if not grant_per_server_consent:
        runtime.runner.record_blocked_attempt(
            experiment=EXPERIMENT_ID,
            actor=f"policy.{RULE_ID}",
            target=server_id,
            reason=(
                "folder trust is not enough; per-server consent is required "
                f"to start {server_id!r}"
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
                    "type": "trust_decision",
                    "folder_trusted": True,
                    "per_server_consent": False,
                    "started_server": None,
                    "capability_diff": list(
                        _PROJECT_MCP_CONFIG["mcpServers"][server_id][
                            "capabilities"
                        ]
                    ),
                }
            ],
        )

    runtime.per_server_consent[server_id] = True
    record = _record_start(runtime, server_id=server_id, session_id=session_id)
    return DemoResult(
        experiment=EXPERIMENT_ID,
        mode="defended",
        violation_detected=False,
        secret_exfiltrated=False,
        blocked_by=[],
        events=[
            {
                "type": "trust_decision",
                "folder_trusted": True,
                "per_server_consent": True,
                "started_server": server_id,
                "started_record": record,
            }
        ],
    )
