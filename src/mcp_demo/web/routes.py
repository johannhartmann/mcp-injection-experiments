"""HTTP surface for the audit / telemetry dashboard.

The routes are deliberately small:

- ``POST /demo/scenario/{experiment_id}`` runs a single experiment scenario
  by dispatching to its ``run_scenario`` helper. The body is
  ``{"mode": "vulnerable" | "defended", "session_id": "..."}``.
- ``GET /demo/events`` lists the unified TelemetryEvent stream. Filters:
  ``?session_id=...`` and ``?experiment=...``. Returns JSON when the
  ``Accept`` header asks for it (default), otherwise a tiny HTML view.
- ``POST /demo/reset`` clears in-memory events for a given session;
  requires the ``X-Demo-Admin-Token`` header to match the configured
  admin token.

All routes share the same Origin allowlist policy as the MCP transport.
"""

from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from mcp_demo.shared.results import DemoResult
from mcp_demo.shared.telemetry import TelemetryView


def _origin_ok(request: Request) -> bool:
    settings = request.app.state.settings
    origin = request.headers.get("origin")
    return origin is not None and origin in settings.allowed_origins


def _forbidden(reason: str) -> JSONResponse:
    return JSONResponse(
        status_code=403, content={"error": "forbidden", "reason": reason}
    )


def _render_html_events(events: list[dict[str, Any]]) -> str:
    rows = []
    for event in events:
        rows.append(
            "<tr>"
            f"<td>{event['ts']}</td>"
            f"<td>{event['session_id'] or ''}</td>"
            f"<td>{event['experiment']}</td>"
            f"<td>{event['mode']}</td>"
            f"<td>{event['event_type']}</td>"
            f"<td>{event['severity']}</td>"
            f"<td><pre>{event['message']}</pre></td>"
            "</tr>"
        )
    body = "".join(rows) or "<tr><td colspan='7'><em>no events</em></td></tr>"
    return (
        "<!doctype html><html><head><title>Demo Events</title>"
        "<style>"
        "body{font-family:system-ui;margin:1.5rem;}"
        "table{border-collapse:collapse;width:100%;font-size:0.85rem;}"
        "th,td{border:1px solid #ddd;padding:0.3rem 0.5rem;text-align:left;vertical-align:top;}"
        "th{background:#f3f3f3;}"
        "tr:nth-child(even){background:#fafafa;}"
        "pre{margin:0;white-space:pre-wrap;}"
        "</style>"
        "</head><body>"
        "<h1>Demo Events</h1>"
        "<table><thead><tr>"
        "<th>ts</th><th>session</th><th>experiment</th><th>mode</th>"
        "<th>event_type</th><th>severity</th><th>message</th>"
        "</tr></thead><tbody>"
        f"{body}"
        "</tbody></table>"
        "</body></html>"
    )


def build_demo_router(
    *,
    scenario_runners: dict[str, Callable[[str, str], DemoResult]],
    telemetry_view: TelemetryView,
    admin_token: str,
) -> APIRouter:
    router = APIRouter(prefix="/demo")

    @router.post("/scenario/{experiment_id}")
    async def run_scenario(experiment_id: str, request: Request) -> Response:
        if not _origin_ok(request):
            return _forbidden("origin not allowlisted")
        runner = scenario_runners.get(experiment_id)
        if runner is None:
            return JSONResponse(
                status_code=404,
                content={"error": "unknown_experiment", "id": experiment_id},
            )
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400, content={"error": "invalid_json"}
            )
        mode = payload.get("mode", "defended")
        session_id = payload.get("session_id", "default")
        result = runner(mode, session_id)
        return JSONResponse(content=result.model_dump())

    @router.get("/events")
    async def list_events(request: Request) -> Response:
        if not _origin_ok(request):
            return _forbidden("origin not allowlisted")
        session_id = request.query_params.get("session_id")
        experiment = request.query_params.get("experiment")
        events = telemetry_view.list_events(
            session_id=session_id, experiment=experiment
        )
        events_payload = [e.model_dump() for e in events]
        accept = request.headers.get("accept", "")
        if "text/html" in accept and "application/json" not in accept:
            html = _render_html_events(events_payload)
            return HTMLResponse(html)
        return JSONResponse(content={"events": events_payload})

    @router.post("/reset")
    async def reset(request: Request) -> Response:
        if not _origin_ok(request):
            return _forbidden("origin not allowlisted")
        provided = request.headers.get("x-demo-admin-token")
        if not provided or provided != admin_token:
            return JSONResponse(
                status_code=401,
                content={"error": "admin_token_required"},
            )
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400, content={"error": "invalid_json"}
            )
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            return JSONResponse(
                status_code=400, content={"error": "session_id_required"}
            )
        telemetry_view.reset_session(session_id)
        return JSONResponse({"reset": session_id})

    return router
