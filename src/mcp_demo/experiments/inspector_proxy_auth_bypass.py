"""Bounded MCP Inspector / devtool auth-bypass RCE-class demo.

Inspired by CVE-2025-49596 (MCP Inspector). The vulnerable mode accepts
an unauthenticated launch request and creates a bounded proof file via
``ImpactRunner.write_sandbox_file``. There is no real subprocess. The
defended mode requires an admin token and a matching Origin header.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mcp_demo.shared.canary import Canary, issue_canary
from mcp_demo.shared.impact import ImpactEvent, ImpactLedger, ImpactRunner
from mcp_demo.shared.mock_inbox import MockInbox
from mcp_demo.shared.mock_sinks import MockSink
from mcp_demo.shared.results import DemoResult


EXPERIMENT_ID = "remote-inspector-proxy-auth-bypass"
ENTRYPOINT = "/mcp/inspector-proxy-auth-bypass"
RULE_ID = "inspector_proxy_auth_policy"
EXPECTED_ADMIN_TOKEN = "demo-admin-token"
EXPECTED_ORIGIN = "http://127.0.0.1:8000"


@dataclass
class InspectorProxyAuthBypassRuntime:
    canary: Canary
    sink: MockSink
    ledger: ImpactLedger
    runner: ImpactRunner


def build_default_runtime(
    *, sandbox_dir: Path, var_dir: Path
) -> InspectorProxyAuthBypassRuntime:
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
    return InspectorProxyAuthBypassRuntime(
        canary=canary, sink=sink, ledger=ledger, runner=runner
    )


def run_scenario(
    *,
    mode: Literal["vulnerable", "defended"],
    session_id: str,
    runtime: InspectorProxyAuthBypassRuntime,
    admin_token: str | None = None,
    origin: str | None = None,
) -> DemoResult:
    if mode == "vulnerable":
        # Vulnerable: launch request needs no auth.
        artifact = runtime.runner.write_sandbox_file(
            relative_name=f"inspector-rce-proof-{session_id}.txt",
            canary=runtime.canary,
            session_id=session_id,
        )
        return DemoResult(
            experiment=EXPERIMENT_ID,
            mode="vulnerable",
            violation_detected=True,
            secret_exfiltrated=False,
            blocked_by=[],
            events=[
                {
                    "type": "bounded_rce_proof",
                    "artifact": str(artifact),
                    "auth_checked": False,
                    "would_execute": False,
                    "note": "no real subprocess; bounded proof file only",
                }
            ],
        )

    # defended: require admin token + matching Origin.
    auth_ok = admin_token is not None and admin_token == EXPECTED_ADMIN_TOKEN
    origin_ok = origin == EXPECTED_ORIGIN
    if not (auth_ok and origin_ok):
        reason = (
            "missing or wrong admin token"
            if not auth_ok
            else f"origin {origin!r} not in allowlist"
        )
        runtime.runner.record_blocked_attempt(
            experiment=EXPERIMENT_ID,
            actor=f"policy.{RULE_ID}",
            target="inspector-proxy.launch_server",
            reason=reason,
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
                    "type": "auth_decision",
                    "check": "admin_token" if not auth_ok else "origin",
                    "reason": reason,
                    "would_execute": False,
                }
            ],
        )
    return DemoResult(
        experiment=EXPERIMENT_ID,
        mode="defended",
        violation_detected=False,
        secret_exfiltrated=False,
        blocked_by=[],
        events=[],
    )


# --- MCP servers (one per mode) ------------------------------------------

from mcp.server.fastmcp import FastMCP  # noqa: E402

from mcp_demo.shared.mcp_helpers import make_fastmcp  # noqa: E402


def build_mcp_servers(
    *,
    runtime: InspectorProxyAuthBypassRuntime,
    server_name: str,
    server_version: str,  # noqa: ARG001
    allowed_origins: tuple[str, ...] = (),
) -> dict[str, FastMCP]:
    """Two real MCP servers. Each exposes launch_server (the
    Inspector-proxy-style entry point) plus run_demo. Vulnerable mode
    creates the bounded proof file with no auth check; defended mode
    requires admin_token and origin arguments."""

    def _build(*, mode: Literal["vulnerable", "defended"]) -> FastMCP:
        server = make_fastmcp(
            name=f"{server_name}.inspector-proxy-auth-bypass.{mode}",
            instructions=(
                "inspector-proxy vulnerable demo: launch_server creates a "
                "bounded sandbox proof file with no admin token check."
                if mode == "vulnerable"
                else "inspector-proxy defended demo: launch_server requires "
                "the admin token and an allowlisted Origin argument."
            ),
            allowed_origins=allowed_origins,
        )

        @server.tool(
            name="launch_server",
            description=(
                "Simulate launching an MCP server through the Inspector "
                "proxy. Vulnerable mode does not check arguments. "
                "Defended mode requires admin_token + origin to match."
            ),
        )
        def launch_server(
            session_id: str = f"mcp-{mode}",
            admin_token: str = "",
            origin: str = "",
        ) -> dict:  # noqa: D401
            result = run_scenario(
                mode=mode,
                session_id=session_id,
                runtime=runtime,
                admin_token=admin_token or None,
                origin=origin or None,
            )
            return result.model_dump()

        @server.tool(
            name="run_demo",
            description="Run the canonical scenario and return DemoResult.",
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
