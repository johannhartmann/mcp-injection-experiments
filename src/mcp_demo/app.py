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

from pathlib import Path
from typing import Callable

from fastapi import FastAPI
from fastapi.responses import JSONResponse

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
    build_endpoint as build_direct_poisoning,
    run_scenario as run_direct_poisoning_scenario,
)
from mcp_demo.experiments.registry import ExperimentRegistry
from mcp_demo.experiments.registry_rug_pull import (
    build_default_runtime as build_registry_rug_pull_runtime,
    run_scenario as run_registry_rug_pull_scenario,
)
from mcp_demo.experiments.sleeper_rug_pull import (
    build_default_runtime as build_sleeper_rug_pull_runtime,
    run_scenario as run_sleeper_rug_pull_scenario,
)
from mcp_demo.experiments.ssrf_metadata import (
    build_default_runtime as build_ssrf_runtime,
    run_scenario as run_ssrf_scenario,
)
from mcp_demo.experiments.tool_shadowing import (
    build_default_runtime as build_tool_shadowing_runtime,
    run_scenario as run_tool_shadowing_scenario,
)
from mcp_demo.shared.impact import ImpactLedger
from mcp_demo.shared.results import DemoResult
from mcp_demo.shared.telemetry import TelemetryView
from mcp_demo.transport.streamable_http import (
    SessionStore,
    build_endpoint_router,
)
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
    registry = registry or ExperimentRegistry.from_directory(_default_manifest_dir())

    app = FastAPI(
        title=settings.server_name,
        version=settings.server_version,
    )
    app.state.settings = settings
    app.state.registry = registry
    app.state.sessions = SessionStore()

    sandbox_dir = _repo_root() / "sandbox"
    var_dir = _repo_root() / "var"

    runtimes: dict[str, object] = {}
    scenario_runners: dict[str, Callable[[str, str], DemoResult]] = {}
    ledgers: list[ImpactLedger] = []

    if "remote-direct-poisoning" in registry:
        rt = build_direct_poisoning_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-direct-poisoning"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-direct-poisoning"] = (
            lambda mode, sid, _rt=rt: run_direct_poisoning_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
        )
        endpoint = build_direct_poisoning(
            runtime=rt,
            server_name=settings.server_name,
            server_version=settings.server_version,
        )
        app.include_router(
            build_endpoint_router(
                endpoint=endpoint,
                sessions=app.state.sessions,
                settings=settings,
            )
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

    if "remote-sleeper-rug-pull" in registry:
        rt = build_sleeper_rug_pull_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-sleeper-rug-pull"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-sleeper-rug-pull"] = (
            lambda mode, sid, _rt=rt: run_sleeper_rug_pull_scenario(
                mode=mode, session_id=sid, runtime=_rt
            )
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

    if "remote-cross-session-context-leak" in registry:
        rt = build_cross_session_runtime(sandbox_dir=sandbox_dir, var_dir=var_dir)
        runtimes["remote-cross-session-context-leak"] = rt
        ledgers.append(rt.ledger)
        scenario_runners["remote-cross-session-context-leak"] = (
            lambda mode, sid, _rt=rt: run_cross_session_scenario(
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
        )
    )

    return app
