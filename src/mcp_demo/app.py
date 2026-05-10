"""FastAPI application factory for the MCP demo.

The app exposes:

- ``GET /healthz`` - liveness probe; no Origin check.
- ``GET /readyz`` - readiness probe; reports manifest count.
- ``POST /mcp/<experiment>`` - one Streamable-HTTP MCP endpoint per
  registered experiment.

Endpoints are wired from
:class:`mcp_demo.experiments.registry.ExperimentRegistry` so manifests stay
the single source of truth: only experiments that were validated by the
manifest schema can register a route.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from mcp_demo.config import DemoSettings
from mcp_demo.experiments.direct_poisoning import (
    build_endpoint as build_direct_poisoning,
)
from mcp_demo.experiments.registry import ExperimentRegistry
from mcp_demo.transport.streamable_http import (
    SessionStore,
    build_endpoint_router,
)


def _default_manifest_dir() -> Path:
    # Repo-root/experiments/manifests at runtime.
    return Path(__file__).resolve().parents[2] / "experiments" / "manifests"


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

    # Experiment endpoints. Today only direct-poisoning is wired up; future
    # prompts will register more from the registry as they get implemented.
    if "remote-direct-poisoning" in registry:
        endpoint = build_direct_poisoning(
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

    return app
