"""Side-by-side comparison page for vulnerable vs defended runs.

The compare page is the highest-pedagogical-value surface in the demo:
clicking a single button triggers both modes of the same experiment,
fetches the resulting tool descriptions from each FastMCP server, runs
each scenario, and renders the two outcomes next to each other so the
delta - poisoned vs sanitised description, allowed leak vs blocked
attempt, mock-inbox row vs telemetry block event - is visible in one
view.
"""

from __future__ import annotations

import difflib
import html
import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from mcp.server.fastmcp import FastMCP

from mcp_demo.experiments.registry import ExperimentRegistry
from mcp_demo.shared.results import DemoResult
from mcp_demo.shared.telemetry import TelemetryEvent


_STYLE = """
:root { color-scheme: light dark; }
body { font-family: system-ui, sans-serif; max-width: 1400px; margin: 1.2rem auto;
       padding: 0 1rem; line-height: 1.45; }
h1 { margin: 0 0 0.4rem 0; font-size: 1.4rem; }
.crumbs { font-size: 0.85rem; color: #666; margin-bottom: 1rem; }
.crumbs a { color: inherit; }
.badges { font-size: 0.75rem; color: #555; margin-bottom: 1rem; }
.badge { display: inline-block; padding: 0.05rem 0.45rem; margin-right: 0.3rem;
         border: 1px solid #ccc; border-radius: 3px; }
.badge.owasp { background: #eef2ff; color: #243; }
.badge.trap { background: #fff3e0; color: #421; }
.badge.surface { background: #f3f3f3; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.col { border: 1px solid #ddd; border-radius: 6px; padding: 0.9rem 1rem;
       background: #fafafa; }
.col.vuln { border-left: 4px solid #d33; }
.col.def { border-left: 4px solid #2a8; }
.col h2 { margin: 0 0 0.4rem 0; font-size: 1.05rem; }
.col h3 { font-size: 0.9rem; margin: 0.9rem 0 0.3rem 0; color: #444;
          text-transform: uppercase; letter-spacing: 0.04em; }
pre { background: #fff; border: 1px solid #ddd; padding: 0.6rem; margin: 0.3rem 0;
      overflow-x: auto; font-size: 0.78rem; white-space: pre-wrap; }
.diff-line { font-family: ui-monospace, monospace; font-size: 0.78rem;
             padding: 0 0.3rem; }
.diff-add { background: #dcfce7; color: #064; }
.diff-del { background: #fee2e2; color: #611; }
.diff-eq  { color: #555; }
.tool { border: 1px solid #eee; border-radius: 4px; padding: 0.4rem 0.6rem;
        margin-bottom: 0.4rem; background: #fff; font-size: 0.85rem; }
.tool .name { font-family: ui-monospace, monospace; font-weight: 600; }
.tool details { margin-top: 0.2rem; }
.tool details summary { cursor: pointer; font-size: 0.8rem; color: #555; }
.kv { font-size: 0.85rem; }
.kv code { background: rgba(0,0,0,0.06); padding: 0 0.25rem; border-radius: 3px; }
.event { border: 1px solid #eee; border-radius: 4px; padding: 0.35rem 0.55rem;
         margin-bottom: 0.35rem; font-size: 0.8rem; background: #fff; }
.event.warn { border-left: 3px solid #d33; }
.event.info { border-left: 3px solid #888; }
.summary-row { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.4rem; }
.pill { padding: 0.05rem 0.45rem; border-radius: 999px; font-size: 0.75rem;
        border: 1px solid #ccc; background: #fff; }
.pill.bad { background: #fee2e2; color: #611; border-color: #f99; }
.pill.good { background: #dcfce7; color: #064; border-color: #6c7; }
@media (prefers-color-scheme: dark) {
  body { background: #15161a; color: #ddd; }
  .col { background: #1c1d24; border-color: #2c2e36; }
  .col.vuln { border-left-color: #ff6b6b; }
  .col.def { border-left-color: #6dd5b1; }
  pre, .tool, .event { background: #21232a; border-color: #2c2e36; color: #ddd; }
  .diff-add { background: #14361f; color: #b6e8c1; }
  .diff-del { background: #3a1212; color: #f4b6b6; }
  .pill { background: #2c2e36; color: #ddd; border-color: #444; }
  .pill.bad { background: #3a1212; color: #f4b6b6; border-color: #722; }
  .pill.good { background: #14361f; color: #b6e8c1; border-color: #2a5; }
  .badge.owasp { background: #1d2542; color: #c8d1ff; border-color: #344; }
  .badge.trap { background: #3a2c12; color: #f0c178; border-color: #533; }
  .badge.surface { background: #2c2e36; }
  a { color: #8bb6ff; }
}
""".strip()


def _diff_html(left: str, right: str) -> str:
    """Word-level-ish diff using difflib's ndiff. Cheap but readable."""

    matcher = difflib.SequenceMatcher(a=left.splitlines(), b=right.splitlines())
    out_left: list[str] = []
    out_right: list[str] = []
    for tag, a1, a2, b1, b2 in matcher.get_opcodes():
        for line in left.splitlines()[a1:a2]:
            cls = "diff-eq" if tag == "equal" else "diff-del"
            out_left.append(
                f'<div class="diff-line {cls}">{html.escape(line) or "&nbsp;"}</div>'
            )
        for line in right.splitlines()[b1:b2]:
            cls = "diff-eq" if tag == "equal" else "diff-add"
            out_right.append(
                f'<div class="diff-line {cls}">{html.escape(line) or "&nbsp;"}</div>'
            )
    return (
        '<div class="cols">'
        f'<div class="col vuln"><h3>poisoned</h3>{"".join(out_left)}</div>'
        f'<div class="col def"><h3>sanitised</h3>{"".join(out_right)}</div>'
        '</div>'
    )


async def _list_tool_descriptions(server: FastMCP) -> list[dict[str, Any]]:
    tools = await server.list_tools()
    return [
        {
            "name": t.name,
            "description": t.description or "",
            "input_schema": t.inputSchema,
        }
        for t in tools
    ]


def _format_tool(tool: dict[str, Any]) -> str:
    schema_json = html.escape(json.dumps(tool["input_schema"], indent=2))
    return (
        '<div class="tool">'
        f'<div class="name">{html.escape(tool["name"])}</div>'
        '<details><summary>description</summary>'
        f'<pre>{html.escape(tool["description"]) or "<em>(empty)</em>"}</pre>'
        '</details>'
        '<details><summary>inputSchema</summary>'
        f'<pre>{schema_json}</pre>'
        '</details>'
        '</div>'
    )


def _format_result(result: DemoResult) -> str:
    pills: list[str] = []
    pills.append(
        f'<span class="pill {"bad" if result.violation_detected else "good"}">'
        f'violation_detected: {str(result.violation_detected).lower()}</span>'
    )
    pills.append(
        f'<span class="pill {"bad" if result.secret_exfiltrated else "good"}">'
        f'secret_exfiltrated: {str(result.secret_exfiltrated).lower()}</span>'
    )
    if result.blocked_by:
        pills.append(
            '<span class="pill good">blocked_by: '
            + html.escape(", ".join(result.blocked_by))
            + "</span>"
        )
    elif result.mode == "vulnerable" and result.violation_detected:
        pills.append('<span class="pill bad">blocked_by: -</span>')
    return (
        '<div class="summary-row">' + "".join(pills) + "</div>"
        '<details><summary>events</summary>'
        f'<pre>{html.escape(json.dumps(result.events, indent=2, ensure_ascii=False))}</pre>'
        "</details>"
    )


def _format_events(events: list[TelemetryEvent]) -> str:
    out: list[str] = []
    for ev in events:
        cls = "warn" if ev.severity in {"warning", "error"} else "info"
        msg = html.escape(ev.message)
        actor = html.escape(ev.data.get("actor") or "")
        out.append(
            f'<div class="event {cls}">'
            f"<strong>{html.escape(ev.event_type)}</strong> "
            f'<span style="color:#888">{html.escape(ev.ts)}</span><br>'
            f"{msg}"
            f'<br><small style="color:#888">actor: {actor}</small>'
            "</div>"
        )
    return "".join(out) or '<em style="color:#888">no events</em>'


def _origin_ok(request: Request) -> bool:
    settings = request.app.state.settings
    origin = request.headers.get("origin")
    if origin is None:
        return False
    return origin in settings.allowed_origins


def build_compare_router(*, registry: ExperimentRegistry) -> APIRouter:
    router = APIRouter(prefix="/demo")

    @router.get("/compare/{experiment_id}")
    async def compare(experiment_id: str, request: Request) -> Response:
        # The compare page is read-only and idempotent enough to be reachable
        # without a posted Origin (a fresh tab navigation has none in many
        # browser flows). The buttons it links to are still Origin-checked.
        if request.headers.get("origin") and not _origin_ok(request):
            return JSONResponse(
                status_code=403, content={"error": "origin not allowlisted"}
            )

        if experiment_id not in registry:
            return JSONResponse(
                status_code=404,
                content={"error": "unknown_experiment", "id": experiment_id},
            )
        manifest = registry.get(experiment_id)
        scenario_runners = request.app.state.scenario_runners
        servers = request.app.state.mcp_servers_by_experiment.get(experiment_id, {})
        telemetry = request.app.state.telemetry

        sid_v = f"compare-vuln-{experiment_id}"
        sid_d = f"compare-def-{experiment_id}"

        # Drive both scenarios.
        result_v: DemoResult = scenario_runners[experiment_id]("vulnerable", sid_v)
        result_d: DemoResult = scenario_runners[experiment_id]("defended", sid_d)

        # Pull tool descriptions from the live FastMCP servers.
        tools_v = await _list_tool_descriptions(servers["vulnerable"]) if "vulnerable" in servers else []
        tools_d = await _list_tool_descriptions(servers["defended"]) if "defended" in servers else []

        # Description diff focuses on the first non-run_demo tool, since
        # that is the experiment's narrative-relevant surface.
        def _narrative_tool(ts: list[dict[str, Any]]) -> dict[str, Any] | None:
            for t in ts:
                if t["name"] != "run_demo":
                    return t
            return ts[0] if ts else None

        nt_v = _narrative_tool(tools_v)
        nt_d = _narrative_tool(tools_d)
        diff_block = ""
        if nt_v and nt_d:
            diff_block = (
                f"<h3>description diff: <code>{html.escape(nt_v['name'])}</code></h3>"
                + _diff_html(nt_v["description"], nt_d["description"])
            )

        events_v = telemetry.list_events(session_id=sid_v)
        events_d = telemetry.list_events(session_id=sid_d)

        owasp_badges = "".join(
            f'<span class="badge owasp">{html.escape(o)}</span>'
            for o in manifest.owasp
        )
        trap_badges = "".join(
            f'<span class="badge trap">{html.escape(t)}</span>'
            for t in manifest.agent_traps
        )
        surface_badges = "".join(
            f'<span class="badge surface">{html.escape(s)}</span>'
            for s in manifest.mcp_surfaces
        )

        slug = experiment_id.removeprefix("remote-")

        body = (
            "<!doctype html><html><head>"
            "<meta charset='utf-8'>"
            f"<title>compare: {html.escape(manifest.title)}</title>"
            f"<style>{_STYLE}</style></head><body>"
            f'<div class="crumbs"><a href="/">home</a> &middot; '
            f'<a href="/demo">demo</a> &middot; '
            f'<a href="/demo/events">events</a> &middot; '
            f'compare: <code>{html.escape(experiment_id)}</code></div>'
            f"<h1>{html.escape(manifest.title)}</h1>"
            f'<div class="badges">{owasp_badges}{trap_badges}{surface_badges}</div>'
            f'<div class="kv">MCP mounts: '
            f'<code>/mcp/{slug}/vulnerable/</code> &middot; '
            f'<code>/mcp/{slug}/defended/</code></div>'
            f"{diff_block}"
            '<div class="cols" style="margin-top:1rem">'
            '<div class="col vuln">'
            "<h2>vulnerable mode</h2>"
            f"{_format_result(result_v)}"
            "<h3>tools/list</h3>"
            + "".join(_format_tool(t) for t in tools_v)
            + "<h3>telemetry</h3>"
            + _format_events(events_v)
            + "</div>"
            '<div class="col def">'
            "<h2>defended mode</h2>"
            f"{_format_result(result_d)}"
            "<h3>tools/list</h3>"
            + "".join(_format_tool(t) for t in tools_d)
            + "<h3>telemetry</h3>"
            + _format_events(events_d)
            + "</div>"
            "</div>"
            "</body></html>"
        )
        return HTMLResponse(body)

    return router
