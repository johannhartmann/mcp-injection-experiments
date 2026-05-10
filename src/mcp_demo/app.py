"""FastAPI application factory for the MCP demo.

The app exposes:

- ``GET /healthz`` / ``GET /readyz`` - liveness and readiness probes.
- ``POST /mcp/<experiment>`` - Streamable-HTTP MCP endpoints (today:
  ``direct-poisoning``).
- ``POST /demo/scenario/<experiment>`` - run a single scenario via the
  experiment's ``run_scenario`` helper.
- ``GET /demo/events`` - unified telemetry list (JSON or HTML).
- ``POST /demo/reset`` - admin-token-gated per-session reset.

Endpoints are wired from the validated
:class:`mcp_demo.experiments.registry.ExperimentRegistry` so manifests
stay the single source of truth.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Callable

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, Response
from mcp.server.fastmcp import FastMCP

from mcp_demo.config import DemoSettings
from mcp_demo.experiments.auth_confused_deputy import (
    build_default_runtime as build_auth_runtime,
    run_scenario as run_auth_scenario,
)
from mcp_demo.experiments.cross_session_leak import (
    build_default_runtime as build_cross_session_runtime,
    run_scenario as run_cross_session_scenario,
)
from mcp_demo.experiments.direct_poisoning import (
    build_default_runtime as build_direct_poisoning_runtime,
    build_mcp_servers as build_direct_poisoning_mcp_servers,
    run_scenario as run_direct_poisoning_scenario,
)
from mcp_demo.experiments.github_issue_leak import (
    build_default_runtime as build_github_issue_leak_runtime,
    run_scenario as run_github_issue_leak_scenario,
)
from mcp_demo.experiments.slack_unfurl_leak import (
    build_default_runtime as build_slack_unfurl_runtime,
    run_scenario as run_slack_unfurl_scenario,
)
from mcp_demo.experiments.filesystem_sandbox_escape import (
    build_default_runtime as build_fs_escape_runtime,
    run_scenario as run_fs_escape_scenario,
)
from mcp_demo.experiments.inspector_proxy_auth_bypass import (
    build_default_runtime as build_inspector_runtime,
    run_scenario as run_inspector_scenario,
)
from mcp_demo.experiments.mcp_remote_auth_endpoint_injection import (
    build_default_runtime as build_mcp_remote_auth_runtime,
    run_scenario as run_mcp_remote_auth_scenario,
)
from mcp_demo.experiments.trustfall_project_mcp_settings import (
    build_default_runtime as build_trustfall_runtime,
    run_scenario as run_trustfall_scenario,
)
from mcp_demo.experiments.cross_agent_config_priv_esc import (
    build_default_runtime as build_cross_agent_runtime,
    run_scenario as run_cross_agent_scenario,
)
from mcp_demo.experiments.promptware_heartbeat import (
    build_default_runtime as build_promptware_runtime,
    run_scenario as run_promptware_scenario,
)
from mcp_demo.experiments.ai_clickfix import (
    build_default_runtime as build_clickfix_runtime,
    run_scenario as run_clickfix_scenario,
)
from mcp_demo.experiments.implicit_tool_poisoning import (
    build_default_runtime as build_implicit_tp_runtime,
    build_mcp_servers as build_implicit_tp_mcp_servers,
    run_scenario as run_implicit_tp_scenario,
)
from mcp_demo.experiments.comment_and_control import (
    build_default_runtime as build_cnc_runtime,
    run_scenario as run_cnc_scenario,
)
from mcp_demo.experiments.agent_traps_hidden_html import (
    build_default_runtime as build_hidden_html_runtime,
    run_scenario as run_hidden_html_scenario,
)
from mcp_demo.experiments.agent_traps_memory_poisoning import (
    build_default_runtime as build_memory_runtime,
    run_scenario as run_memory_scenario,
)
from mcp_demo.experiments.agent_traps_subagent_spawning import (
    build_default_runtime as build_subagent_runtime,
    run_scenario as run_subagent_scenario,
)
from mcp_demo.experiments.agent_traps_approval_fatigue import (
    build_default_runtime as build_approval_runtime,
    run_scenario as run_approval_scenario,
)
from mcp_demo.experiments.agent_traps_sybil_and_fragments import (
    build_default_runtime as build_sybil_runtime,
    run_scenario as run_sybil_scenario,
)
from mcp_demo.experiments.git_filesystem_chain_safe import (
    build_default_runtime as build_git_fs_runtime,
    run_scenario as run_git_fs_scenario,
)
from mcp_demo.experiments.registry import ExperimentRegistry
from mcp_demo.experiments.registry_rug_pull import (
    build_default_runtime as build_registry_rug_pull_runtime,
    run_scenario as run_registry_rug_pull_scenario,
)
from mcp_demo.experiments.sleeper_rug_pull import (
    build_default_runtime as build_sleeper_rug_pull_runtime,
    build_mcp_servers as build_sleeper_rug_pull_mcp_servers,
    run_scenario as run_sleeper_rug_pull_scenario,
)
from mcp_demo.experiments.sampling_abuse import (
    build_default_runtime as build_sampling_abuse_runtime,
    run_scenario as run_sampling_abuse_scenario,
)
from mcp_demo.experiments.ssrf_metadata import (
    build_default_runtime as build_ssrf_runtime,
    run_scenario as run_ssrf_scenario,
)
from mcp_demo.experiments.tool_shadowing import (
    build_default_runtime as build_tool_shadowing_runtime,
    build_mcp_servers as build_tool_shadowing_mcp_servers,
    run_scenario as run_tool_shadowing_scenario,
)
from mcp_demo.shared.impact import ImpactLedger
from mcp_demo.shared.results import DemoResult
from mcp_demo.shared.telemetry import TelemetryView
from mcp_demo.web.landing import render_landing_page
from mcp_demo.web.routes import build_demo_router


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_manifest_dir() -> Path:
    return _repo_root() / "experiments" / "manifests"


def _default_registry_fixtures() -> Path:
    return _repo_root() / "tests" / "fixtures" / "registry"


def create_app(
    *,
    settings: DemoSettings | None = None,
    registry: ExperimentRegistry | None = None,
) -> FastAPI:
    settings = settings or DemoSettings()
    if settings.public_mode:
        settings.validate_for_public_mode()
    registry = registry or ExperimentRegistry.from_directory(_default_manifest_dir())

    # Each mounted FastMCP needs its session-manager started during
    # application lifespan; otherwise the streamable_http_app raises
    # "Task group is not initialized" on the first request. We collect
    # every FastMCP instance we mount and run their session_manager.run()
    # context-managers under a single AsyncExitStack tied to FastAPI's
    # lifespan.
    mcp_servers: list[FastMCP] = []

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with contextlib.AsyncExitStack() as stack:
            for server in mcp_servers:
                await stack.enter_async_context(
                    server.session_manager.run()
                )
            yield

    app = FastAPI(
        title=settings.server_name,
        version=settings.server_version,
        debug=False,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.registry = registry

    sandbox_dir = _repo_root() / "sandbox"
    var_dir = _repo_root() / "var"

    runtimes: dict[str, object] = {}
    scenario_runners: dict[str, Callable[[str, str], DemoResult]] = {}
    ledgers: list[ImpactLedger] = []

    def _mount_mcp(experiment_id: str, builder, rt) -> None:
        """Build and mount a per-mode FastMCP pair for ``experiment_id``."""

        servers = builder(
            runtime=rt,
            server_name=settings.server_name,
            server_version=settings.server_version,
            allowed_origins=settings.allowed_origins,
        )
        for mode, server in servers.items():
            app.mount(
                f"/mcp/{experiment_id.removeprefix('remote-')}/{mode}",
                server.streamable_http_app(),
            )
            mcp_servers.append(server)

    if "remote-direct-poisoning" in registry:
        rt = build_direct_poisoning_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-direct-poisoning"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-direct-poisoning"] = (
            lambda mode, sid, _rt=rt: run_direct_poisoning_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )
        # Mount one official MCP server per mode under
        # /mcp/direct-poisoning/<mode>/. Each server speaks the full
        # Streamable-HTTP transport (initialize, tools/list, tools/call,
        # SSE) via the official mcp Python SDK.
        _mount_mcp(
            "remote-direct-poisoning",
            build_direct_poisoning_mcp_servers,
            rt,
        )

    if "remote-tool-shadowing" in registry:
        rt = build_tool_shadowing_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-tool-shadowing"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-tool-shadowing"] = (
            lambda mode, sid, _rt=rt: run_tool_shadowing_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )
        _mount_mcp("remote-tool-shadowing", build_tool_shadowing_mcp_servers, rt)

    if "remote-sleeper-rug-pull" in registry:
        rt = build_sleeper_rug_pull_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-sleeper-rug-pull"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-sleeper-rug-pull"] = (
            lambda mode, sid, _rt=rt: run_sleeper_rug_pull_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )
        _mount_mcp(
            "remote-sleeper-rug-pull", build_sleeper_rug_pull_mcp_servers, rt
        )

    if "remote-registry-rug-pull" in registry:
        rt = build_registry_rug_pull_runtime(
            sandbox_dir=sandbox_dir,
            var_dir=var_dir,
            registry_dir=_default_registry_fixtures(),
        )
        runtimes["remote-registry-rug-pull"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-registry-rug-pull"] = (
            lambda mode, sid, _rt=rt: run_registry_rug_pull_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-trustfall-project-mcp-settings" in registry:
        rt = build_trustfall_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-trustfall-project-mcp-settings"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-trustfall-project-mcp-settings"] = (
            lambda mode, sid, _rt=rt: run_trustfall_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-cross-session-context-leak" in registry:
        rt = build_cross_session_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-cross-session-context-leak"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-cross-session-context-leak"] = (
            lambda mode, sid, _rt=rt: run_cross_session_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-cross-agent-config-priv-esc" in registry:
        rt = build_cross_agent_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-cross-agent-config-priv-esc"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-cross-agent-config-priv-esc"] = (
            lambda mode, sid, _rt=rt: run_cross_agent_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-promptware-heartbeat" in registry:
        rt = build_promptware_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-promptware-heartbeat"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-promptware-heartbeat"] = (
            lambda mode, sid, _rt=rt: run_promptware_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-ai-clickfix" in registry:
        rt = build_clickfix_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-ai-clickfix"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-ai-clickfix"] = (
            lambda mode, sid, _rt=rt: run_clickfix_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-implicit-tool-poisoning" in registry:
        rt = build_implicit_tp_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-implicit-tool-poisoning"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-implicit-tool-poisoning"] = (
            lambda mode, sid, _rt=rt: run_implicit_tp_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )
        _mount_mcp(
            "remote-implicit-tool-poisoning", build_implicit_tp_mcp_servers, rt
        )

    if "remote-comment-and-control" in registry:
        rt = build_cnc_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-comment-and-control"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-comment-and-control"] = (
            lambda mode, sid, _rt=rt: run_cnc_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-agent-traps-hidden-html" in registry:
        rt = build_hidden_html_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-agent-traps-hidden-html"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-agent-traps-hidden-html"] = (
            lambda mode, sid, _rt=rt: run_hidden_html_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-agent-traps-memory-poisoning" in registry:
        rt = build_memory_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-agent-traps-memory-poisoning"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-agent-traps-memory-poisoning"] = (
            lambda mode, sid, _rt=rt: run_memory_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-agent-traps-subagent-spawning" in registry:
        rt = build_subagent_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-agent-traps-subagent-spawning"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-agent-traps-subagent-spawning"] = (
            lambda mode, sid, _rt=rt: run_subagent_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-agent-traps-approval-fatigue" in registry:
        rt = build_approval_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-agent-traps-approval-fatigue"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-agent-traps-approval-fatigue"] = (
            lambda mode, sid, _rt=rt: run_approval_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-agent-traps-sybil-and-fragments" in registry:
        rt = build_sybil_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-agent-traps-sybil-and-fragments"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-agent-traps-sybil-and-fragments"] = (
            lambda mode, sid, _rt=rt: run_sybil_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-git-filesystem-chain-safe" in registry:
        rt = build_git_fs_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-git-filesystem-chain-safe"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-git-filesystem-chain-safe"] = (
            lambda mode, sid, _rt=rt: run_git_fs_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-github-issue-leak" in registry:
        rt = build_github_issue_leak_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-github-issue-leak"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-github-issue-leak"] = (
            lambda mode, sid, _rt=rt: run_github_issue_leak_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-slack-unfurl-leak" in registry:
        rt = build_slack_unfurl_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-slack-unfurl-leak"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-slack-unfurl-leak"] = (
            lambda mode, sid, _rt=rt: run_slack_unfurl_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-filesystem-sandbox-escape" in registry:
        rt = build_fs_escape_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-filesystem-sandbox-escape"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-filesystem-sandbox-escape"] = (
            lambda mode, sid, _rt=rt: run_fs_escape_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-inspector-proxy-auth-bypass" in registry:
        rt = build_inspector_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-inspector-proxy-auth-bypass"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-inspector-proxy-auth-bypass"] = (
            lambda mode, sid, _rt=rt: run_inspector_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-mcp-remote-auth-endpoint-injection" in registry:
        rt = build_mcp_remote_auth_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-mcp-remote-auth-endpoint-injection"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-mcp-remote-auth-endpoint-injection"] = (
            lambda mode, sid, _rt=rt: run_mcp_remote_auth_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-auth-confused-deputy" in registry:
        rt = build_auth_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-auth-confused-deputy"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-auth-confused-deputy"] = (
            lambda mode, sid, _rt=rt: run_auth_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-sampling-abuse" in registry:
        rt = build_sampling_abuse_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-sampling-abuse"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-sampling-abuse"] = (
            lambda mode, sid, _rt=rt: run_sampling_abuse_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    if "remote-ssrf-metadata" in registry:
        rt = build_ssrf_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-ssrf-metadata"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-ssrf-metadata"] = (
            lambda mode, sid, _rt=rt: run_ssrf_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )

    app.state.runtimes = runtimes
    app.state.telemetry = TelemetryView(ledgers)

    @app.get("/", include_in_schema=False)
    async def landing() -> Response:
        return HTMLResponse(
            render_landing_page(
                registry=registry,
                allowed_origins=settings.allowed_origins,
                public_mode=settings.public_mode,
            )
        )

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "name": settings.server_name})

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ready",
                "experiments": registry.list_ids(),
                "experiment_count": len(registry),
            }
        )

    app.include_router(
        build_demo_router(
            scenario_runners=scenario_runners,
            telemetry_view=app.state.telemetry,
            admin_token=settings.admin_token,
            registry=registry,
        )
    )

    return app
