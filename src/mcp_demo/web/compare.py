"""Side-by-side comparison page for vulnerable vs defended runs.

The compare page is the demo's primary teaching surface. The layout
leads with the *concrete session artefact* (the "What just happened"
panel summarises this run's timestamp, impact type, artefact path and
canary id per mode) and the poisoned-vs-sanitised tool description
diff, so the first thing a visitor sees is what their click produced.
The per-mode columns follow with the result pills and the structured
artefact cards. The manifest's hand-written narrative paragraph is
rendered last inside each column as "Background", and the experiment
docstring sits below the columns as "Background on this attack class".
Raw outputs (full DemoResult JSON, full tools/list with schemas, full
telemetry rows, Inspector hints) live in collapsed ``<details>`` at
the bottom.
"""

from __future__ import annotations

import difflib
import html
import importlib
import json
import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from mcp.server.fastmcp import FastMCP

from mcp_demo.experiments.registry import ExperimentRegistry
from mcp_demo.shared.results import DemoResult
from mcp_demo.shared.telemetry import TelemetryEvent


_STYLE = """
:root { color-scheme: light dark; }
body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 1.2rem auto;
       padding: 0 1rem; line-height: 1.5; color: #222; }
h1 { margin: 0 0 0.4rem 0; font-size: 1.5rem; }
h2 { margin: 0.2rem 0 0.4rem 0; font-size: 1.1rem; }
h3 { font-size: 0.85rem; margin: 1.1rem 0 0.4rem 0; color: #555;
     text-transform: uppercase; letter-spacing: 0.05em; }
.crumbs { font-size: 0.85rem; color: #666; margin-bottom: 1rem; }
.crumbs a { color: inherit; }
.badges { font-size: 0.75rem; color: #555; margin-bottom: 1rem; }
.badge { display: inline-block; padding: 0.05rem 0.45rem; margin-right: 0.3rem;
         border: 1px solid #ccc; border-radius: 3px; }
.badge.owasp { background: #eef2ff; color: #243; }
.badge.trap { background: #fff3e0; color: #421; }
.badge.surface { background: #f3f3f3; }
.intro { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
         padding: 0.8rem 1rem; margin: 0 0 1.2rem 0; }
.intro p { margin: 0.25rem 0; }
.intro.context { background: #f5f5f7; margin-top: 1.6rem; }
.intro.context .context-label { font-size: 0.7rem; text-transform: uppercase;
                                letter-spacing: 0.05em; color: #888;
                                margin-bottom: 0.3rem; font-weight: 600; }
.session-summary { background: #fffbe6; border: 1px solid #f0d779;
                   border-radius: 6px; padding: 0.7rem 1rem;
                   margin: 0 0 1rem 0; }
.session-summary h3 { color: #5a4400; margin: 0 0 0.4rem 0; font-size: 0.78rem; }
.session-summary .row { padding: 0.3rem 0; border-bottom: 1px dashed #e8d57f; }
.session-summary .row:last-child { border-bottom: 0; padding-bottom: 0; }
.session-summary .role { font-size: 0.78rem; font-weight: 600;
                         padding: 0.05rem 0.4rem; border-radius: 3px;
                         margin-right: 0.4rem; }
.session-summary .row.vuln .role { background: #fee2e2; color: #b91c1c; }
.session-summary .row.def  .role { background: #dcfce7; color: #047857; }
.session-summary .sid { font-size: 0.75rem; color: #555; margin-right: 0.4rem; }
.session-summary .ts  { font-size: 0.72rem; color: #777;
                        font-family: ui-monospace, monospace;
                        margin-right: 0.4rem; }
.session-summary .what { font-size: 0.88rem; margin-top: 0.15rem; }
.session-summary .what code { font-size: 0.82rem;
                              background: rgba(0,0,0,0.05);
                              padding: 0 0.25rem; border-radius: 3px; }
.background { margin-top: 0.9rem; padding-top: 0.5rem;
              border-top: 1px dashed #ddd; }
.background-label { font-size: 0.7rem; text-transform: uppercase;
                    letter-spacing: 0.05em; color: #888;
                    margin-bottom: 0.2rem; font-weight: 600; }
.background .outcome { font-size: 0.85rem; color: #555;
                       font-style: italic; margin: 0; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.col { border: 1px solid #ddd; border-radius: 6px; padding: 0.9rem 1rem;
       background: #fafafa; }
.col.vuln { border-left: 5px solid #d33; }
.col.def  { border-left: 5px solid #2a8; }
.headline { font-size: 1rem; margin: 0 0 0.5rem 0; font-weight: 600; }
.headline.bad  { color: #b91c1c; }
.headline.good { color: #047857; }
.outcome { font-size: 0.95rem; margin: 0.3rem 0 0.6rem 0; }
.artefact { background: #fff; border: 1px solid #e2e8f0; border-radius: 4px;
            padding: 0.5rem 0.7rem; margin: 0.4rem 0; font-size: 0.85rem; }
.artefact .label { font-size: 0.72rem; color: #666; text-transform: uppercase;
                   letter-spacing: 0.04em; margin-bottom: 0.2rem; }
.artefact code { font-size: 0.78rem; }
.artefact pre  { margin: 0.2rem 0 0 0; font-size: 0.78rem; white-space: pre-wrap;
                 word-break: break-word; }
.kv { font-size: 0.85rem; }
.kv code { background: rgba(0,0,0,0.06); padding: 0 0.25rem; border-radius: 3px; }
.diff-line { font-family: ui-monospace, monospace; font-size: 0.78rem;
             padding: 0 0.3rem; }
.diff-add { background: #dcfce7; color: #064; }
.diff-del { background: #fee2e2; color: #611; }
.diff-eq  { color: #777; }
details.dev { margin-top: 1.5rem; border-top: 1px solid #e2e8f0; padding-top: 0.8rem;}
details.dev summary { cursor: pointer; font-size: 0.85rem; color: #555; }
details.dev pre { background: #fff; border: 1px solid #ddd; padding: 0.6rem;
                  font-size: 0.78rem; white-space: pre-wrap; }
.tool { border: 1px solid #eee; border-radius: 4px; padding: 0.4rem 0.6rem;
        margin-bottom: 0.4rem; background: #fff; font-size: 0.85rem; }
.tool .name { font-family: ui-monospace, monospace; font-weight: 600; }
.pill { padding: 0.05rem 0.45rem; border-radius: 999px; font-size: 0.75rem;
        border: 1px solid #ccc; background: #fff; }
.pill.bad  { background: #fee2e2; color: #611; border-color: #f99; }
.pill.good { background: #dcfce7; color: #064; border-color: #6c7; }
.summary-row { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.4rem; }
@media (prefers-color-scheme: dark) {
  body { background: #15161a; color: #ddd; }
  .intro { background: #1c1d24; border-color: #2c2e36; }
  .intro.context { background: #1a1b20; }
  .intro.context .context-label { color: #888; }
  .col { background: #1c1d24; border-color: #2c2e36; }
  .artefact, .tool, details.dev pre { background: #21232a; border-color: #2c2e36;
                                      color: #ddd; }
  .headline.bad  { color: #f87171; }
  .headline.good { color: #6ee7b7; }
  .pill { background: #2c2e36; color: #ddd; border-color: #444; }
  .pill.bad { background: #3a1212; color: #f4b6b6; border-color: #722; }
  .pill.good{ background: #14361f; color: #b6e8c1; border-color: #2a5; }
  .badge.owasp { background: #1d2542; color: #c8d1ff; border-color: #344; }
  .badge.trap  { background: #3a2c12; color: #f0c178; border-color: #533; }
  .badge.surface{background: #2c2e36; }
  .diff-add { background: #14361f; color: #b6e8c1; }
  .diff-del { background: #3a1212; color: #f4b6b6; }
  .session-summary { background: #3a2e0d; border-color: #6b552b; }
  .session-summary h3 { color: #f0c178; }
  .session-summary .row { border-bottom-color: #5a4a25; }
  .session-summary .row.vuln .role { background: #3a1212; color: #f87171; }
  .session-summary .row.def  .role { background: #14361f; color: #6ee7b7; }
  .session-summary .sid { color: #999; }
  .session-summary .ts { color: #aaa; }
  .session-summary .what code { background: rgba(255,255,255,0.08); }
  .background { border-top-color: #2c2e36; }
  .background-label { color: #888; }
  .background .outcome { color: #aaa; }
  a { color: #8bb6ff; }
}
""".strip()


# ---------------------------------------------------------------------------
# Narrative helpers


def _humanize(snake_or_kebab: str) -> str:
    """Turn ``foo_bar-baz`` into ``Foo bar baz``."""
    if not snake_or_kebab:
        return ""
    words = re.split(r"[_\-]+", snake_or_kebab)
    return " ".join(words).strip().capitalize()


def _module_for_experiment(experiment_id: str) -> Any | None:
    """Map ``remote-foo-bar`` -> ``mcp_demo.experiments.foo_bar``."""
    slug = experiment_id.removeprefix("remote-").replace("-", "_")
    candidate = f"mcp_demo.experiments.{slug}"
    try:
        return importlib.import_module(candidate)
    except ImportError:
        return None


def _experiment_docstring(experiment_id: str) -> str:
    """Return the experiment module's docstring (the short paragraph
    each experiment file opens with) so the compare page can show it
    as the narrative intro."""
    module = _module_for_experiment(experiment_id)
    if module is None or not module.__doc__:
        return ""
    doc = module.__doc__.strip()
    return doc


# ---------------------------------------------------------------------------
# Diff + tool helpers


def _diff_html(left: str, right: str) -> str:
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


# ---------------------------------------------------------------------------
# Outcome cards


def _result_pills(result: DemoResult) -> str:
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
    return '<div class="summary-row">' + "".join(pills) + "</div>"


def _artefact_card(label: str, body_html: str) -> str:
    return (
        '<div class="artefact">'
        f'<div class="label">{html.escape(label)}</div>'
        f"{body_html}"
        "</div>"
    )


def _format_session_telemetry(events: list[TelemetryEvent]) -> str:
    """Render the impact-telemetry rows recorded during this session in
    plain language: impact_type, actor -> target, and the human-written
    user_visible_summary if present."""
    if not events:
        return _artefact_card(
            "telemetry", '<em style="color:#888">no events recorded</em>'
        )
    lines: list[str] = []
    for ev in events:
        data = ev.data or {}
        impact = data.get("impact_type") or ev.event_type
        actor = data.get("actor") or "?"
        target = data.get("target") or "?"
        decision = data.get("policy_decision") or ""
        summary = data.get("user_visible_summary") or ev.message or ""
        lines.append(
            f"<div><strong>{html.escape(str(impact))}</strong> "
            f"<code>{html.escape(str(actor))}</code> &rarr; "
            f"<code>{html.escape(str(target))}</code>"
            + (
                f' <span class="pill bad">{html.escape(str(decision))}</span>'
                if decision == "blocked"
                else (
                    f' <span class="pill good">{html.escape(str(decision))}</span>'
                    if decision
                    else ""
                )
            )
            + "</div>"
            + (
                f'<div style="font-size:0.85em;color:#555;margin-left:0.5rem;">'
                f"{html.escape(str(summary))}</div>"
                if summary
                else ""
            )
        )
    return _artefact_card("telemetry events for this run", "".join(lines))


def _summarise_value(v: Any, *, max_len: int = 160) -> str:
    """Compact one-line summary of any value for the primary view.

    Lists and dicts are summarised as ``[N items]`` / ``{N keys}``;
    long strings get truncated. The full structured value still lives
    in the developer-view <details> at the bottom of the page.
    """
    if isinstance(v, dict):
        return f"&#x7b;{len(v)} keys&#x7d;"
    if isinstance(v, list):
        if not v:
            return "[]"
        return f"[{len(v)} items]"
    s = str(v)
    if len(s) > max_len:
        return html.escape(s[:max_len] + "...")
    return html.escape(s)


def _format_demo_events(events: list[dict[str, Any]]) -> str:
    """Render the experiment-author-curated DemoResult.events as a
    one-line-per-key card. Nested structures show their shape only;
    the raw JSON lives in the developer-view <details> block."""

    if not events:
        return ""
    blocks: list[str] = []
    for ev in events:
        rows: list[str] = []
        for k, v in ev.items():
            if k == "type":
                continue  # already used as the card label
            key = html.escape(_humanize(str(k)))
            rendered = f"<code>{_summarise_value(v)}</code>"
            rows.append(
                '<div style="display:grid;grid-template-columns:170px 1fr;gap:0.4rem;'
                'margin:0.15rem 0;align-items:start;">'
                f'<div style="color:#666;font-size:0.78rem;">{key}</div>'
                f"<div style='font-size:0.85rem;'>{rendered}</div></div>"
            )
        blocks.append(
            _artefact_card(
                str(ev.get("type", "event")).replace("_", " "),
                "".join(rows),
            )
        )
    return "".join(blocks)


def _session_summary_row(
    *,
    mode: str,
    sid: str,
    result: DemoResult,
    events: list[TelemetryEvent],
    fallback_artefact: str | None,
) -> str:
    """One concrete line per mode for the "What just happened" panel.

    Uses the most recent telemetry event of this session as the source
    of truth for timestamp, artefact path and canary id. Falls back to
    the manifest's declared artefact path when the session produced no
    telemetry (e.g. a defended scenario that short-circuits before any
    impact is recorded)."""

    is_vuln = mode == "vulnerable"
    role_cls = "vuln" if is_vuln else "def"
    role_label = "vulnerable" if is_vuln else "defended"

    last = events[-1] if events else None
    ts = last.ts if last else ""
    data = last.data if last else {}

    if is_vuln and result.violation_detected and not result.blocked_by:
        impact = str(data.get("impact_type") or "side effect")
        artefact = data.get("artifact") or fallback_artefact
        canary = data.get("canary_id")
        what = f"<strong>{html.escape(impact.replace('_', ' '))}</strong> landed"
        if artefact:
            what += f" in <code>{html.escape(str(artefact))}</code>"
        if canary:
            what += f" &middot; canary <code>{html.escape(str(canary))}</code>"
    elif not is_vuln and result.blocked_by:
        rules = ", ".join(result.blocked_by)
        what = (
            f"<strong>blocked</strong> by <code>{html.escape(rules)}</code>"
        )
        artefact = data.get("artifact") or fallback_artefact
        if artefact:
            what += f" &middot; logged to <code>{html.escape(str(artefact))}</code>"
    elif is_vuln:
        what = "run completed without an observable artefact"
    else:
        what = "run completed without firing any policy"

    ts_html = f'<span class="ts">{html.escape(ts)}</span>' if ts else ""
    return (
        f'<div class="row {role_cls}">'
        f'<div>'
        f'<span class="role">{role_label}</span>'
        f'<span class="sid"><code>{html.escape(sid)}</code></span>'
        f"{ts_html}"
        f"</div>"
        f'<div class="what">{what}</div>'
        f"</div>"
    )


def _session_summary_panel(
    *,
    sid_v: str,
    sid_d: str,
    result_v: DemoResult,
    result_d: DemoResult,
    events_v: list[TelemetryEvent],
    events_d: list[TelemetryEvent],
    fallback_artefact_v: str | None,
    fallback_artefact_d: str | None,
) -> str:
    rows = _session_summary_row(
        mode="vulnerable",
        sid=sid_v,
        result=result_v,
        events=events_v,
        fallback_artefact=fallback_artefact_v,
    ) + _session_summary_row(
        mode="defended",
        sid=sid_d,
        result=result_d,
        events=events_d,
        fallback_artefact=fallback_artefact_d,
    )
    return (
        '<section class="session-summary">'
        "<h3>What just happened in your session</h3>"
        f"{rows}"
        "</section>"
    )


def _outcome_text(
    *,
    mode: str,
    narrative_text: str | None,
    user_visible: str | None,
    expected_result: str | None,
    artefacts_fallback: list[str],
    result: DemoResult,
) -> str:
    """Pick the best plain-language description, in priority order:

    1. The manifest's ``narrative.{mode}`` paragraph (preferred).
    2. The legacy ``impact.{mode}.user_visible`` snake_case label,
       humanised.
    3. The legacy ``expected_{mode}_result`` string, humanised.
    4. A synthesised description from the DemoResult and listed
       artefact paths (last-resort fallback).
    """
    if narrative_text:
        return narrative_text
    if user_visible:
        return _humanize(user_visible) + "."
    if expected_result:
        return _humanize(expected_result) + "."
    # Synthesise from DemoResult + safe_impact paths.
    if mode == "vulnerable" and result.violation_detected and not result.blocked_by:
        artefact_str = (
            ", ".join(f"`{a}`" for a in artefacts_fallback)
            if artefacts_fallback
            else "the demo ledger"
        )
        return (
            f"The vulnerable scenario produced an observable side effect in "
            f"{artefact_str}."
        )
    if mode == "defended" and result.blocked_by:
        rules = ", ".join(f"`{r}`" for r in result.blocked_by)
        return f"The defended scenario blocked the action via {rules}."
    return "The scenario ran without an observable violation."


def _outcome_card(
    *,
    mode: str,
    result: DemoResult,
    manifest_impact: Any,
    safe_impact_artifacts: list[str],
    narrative_text: str | None,
    expected_result: str | None,
    mitigations: list[str],
    rule_id: str | None,
    telemetry_events: list[TelemetryEvent],
) -> str:
    is_vulnerable = mode == "vulnerable"
    is_attack_landed = (
        is_vulnerable and result.violation_detected and not result.blocked_by
    )

    if is_attack_landed:
        headline_class = "bad"
        headline = "&#x2717; The attack succeeded"
    elif is_vulnerable:
        headline_class = ""
        headline = "Run completed"
    else:
        headline_class = "good" if result.blocked_by else ""
        headline = (
            "&#x2713; The defense blocked the attack"
            if result.blocked_by
            else "Run completed"
        )

    user_visible = (
        manifest_impact.user_visible if manifest_impact is not None else None
    )
    artefact_path = (
        manifest_impact.artifact if manifest_impact is not None else None
    )

    outcome_paragraph = _outcome_text(
        mode=mode,
        narrative_text=narrative_text,
        user_visible=user_visible,
        expected_result=expected_result,
        artefacts_fallback=safe_impact_artifacts,
        result=result,
    )

    parts: list[str] = []
    parts.append(f'<div class="headline {headline_class}">{headline}</div>')

    # Lead with the concrete artefact — where it landed, what fired,
    # what mitigated it. The narrative paragraph moves to the bottom of
    # the card as "Background" so this section reads as "what happened
    # in *this* session" rather than "what an LLM would do in theory".
    if artefact_path:
        parts.append(
            _artefact_card(
                "where it landed",
                f"<code>{html.escape(artefact_path)}</code>",
            )
        )
    elif safe_impact_artifacts:
        parts.append(
            _artefact_card(
                "where it landed",
                "<ul style='margin:0.2rem 0 0 1rem;padding:0;'>"
                + "".join(
                    f"<li><code>{html.escape(a)}</code></li>"
                    for a in safe_impact_artifacts
                )
                + "</ul>",
            )
        )

    if not is_vulnerable and rule_id and result.blocked_by:
        parts.append(
            _artefact_card(
                "rule that fired",
                f"<code>{html.escape(rule_id)}</code>",
            )
        )

    if not is_vulnerable and mitigations:
        parts.append(
            _artefact_card(
                "mitigations applied",
                "<ul style='margin:0.2rem 0 0 1rem;padding:0;'>"
                + "".join(
                    f"<li><code>{html.escape(m)}</code></li>" for m in mitigations
                )
                + "</ul>",
            )
        )

    parts.append(_format_demo_events(result.events))
    parts.append(_format_session_telemetry(telemetry_events))

    parts.append(
        '<div class="background">'
        '<div class="background-label">Background</div>'
        f'<div class="outcome">{html.escape(outcome_paragraph)}</div>'
        "</div>"
    )
    return "".join(parts)


# ---------------------------------------------------------------------------
# Origin guard


def _origin_ok(request: Request) -> bool:
    settings = request.app.state.settings
    origin = request.headers.get("origin")
    if origin is None:
        return False
    return origin in settings.allowed_origins


# ---------------------------------------------------------------------------
# Router


def build_compare_router(*, registry: ExperimentRegistry) -> APIRouter:
    router = APIRouter(prefix="/demo")

    @router.get("/compare/{experiment_id}")
    async def compare(experiment_id: str, request: Request) -> Response:
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

        result_v: DemoResult = scenario_runners[experiment_id]("vulnerable", sid_v)
        result_d: DemoResult = scenario_runners[experiment_id]("defended", sid_d)

        tools_v = (
            await _list_tool_descriptions(servers["vulnerable"])
            if "vulnerable" in servers
            else []
        )
        tools_d = (
            await _list_tool_descriptions(servers["defended"])
            if "defended" in servers
            else []
        )

        def _narrative_tool(ts: list[dict[str, Any]]) -> dict[str, Any] | None:
            for t in ts:
                if t["name"] != "run_demo":
                    return t
            return ts[0] if ts else None

        nt_v = _narrative_tool(tools_v)
        nt_d = _narrative_tool(tools_d)

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
        base_url = (
            request.headers.get("origin") or str(request.base_url).rstrip("/")
        ).rstrip("/")
        mcp_v_url = f"{base_url}/mcp/{slug}/vulnerable/"
        mcp_d_url = f"{base_url}/mcp/{slug}/defended/"

        # Pull narrative pieces.
        docstring = _experiment_docstring(experiment_id)
        rule_id = None
        module = _module_for_experiment(experiment_id)
        if module is not None:
            rule_id = getattr(module, "RULE_ID", None)

        intro_paragraph = (
            f"<p>{html.escape(docstring)}</p>"
            if docstring
            else (
                f"<p><em>{html.escape(_humanize(manifest.expected_vulnerable_result or ''))} "
                f"vs. {html.escape(_humanize(manifest.expected_defended_result or ''))}</em></p>"
            )
        )

        impact_v = manifest.impact.vulnerable if manifest.impact else None
        impact_d = manifest.impact.defended if manifest.impact else None
        safe_v = (
            manifest.safe_impact.vulnerable_artifacts
            if manifest.safe_impact
            else []
        )
        safe_d = (
            manifest.safe_impact.defended_artifacts
            if manifest.safe_impact
            else []
        )
        narrative_v = (
            manifest.narrative.vulnerable if manifest.narrative else None
        )
        narrative_d = (
            manifest.narrative.defended if manifest.narrative else None
        )

        outcome_v = _outcome_card(
            mode="vulnerable",
            result=result_v,
            manifest_impact=impact_v,
            safe_impact_artifacts=safe_v,
            narrative_text=narrative_v,
            expected_result=manifest.expected_vulnerable_result,
            mitigations=[],
            rule_id=rule_id,
            telemetry_events=events_v,
        )
        outcome_d = _outcome_card(
            mode="defended",
            result=result_d,
            manifest_impact=impact_d,
            safe_impact_artifacts=safe_d,
            narrative_text=narrative_d,
            expected_result=manifest.expected_defended_result,
            mitigations=manifest.mitigations,
            rule_id=rule_id,
            telemetry_events=events_d,
        )

        # Synthesise the "What just happened" top panel so the page leads
        # with concrete session artefacts before any narrative prose.
        fallback_artefact_v = (
            impact_v.artifact
            if impact_v is not None
            else (safe_v[0] if safe_v else None)
        )
        fallback_artefact_d = (
            impact_d.artifact
            if impact_d is not None
            else (safe_d[0] if safe_d else None)
        )
        summary_panel = _session_summary_panel(
            sid_v=sid_v,
            sid_d=sid_d,
            result_v=result_v,
            result_d=result_d,
            events_v=events_v,
            events_d=events_d,
            fallback_artefact_v=fallback_artefact_v,
            fallback_artefact_d=fallback_artefact_d,
        )

        diff_block = ""
        if nt_v and nt_d:
            diff_block = (
                "<details class='dev' open>"
                f"<summary>Tool description that differed: <code>{html.escape(nt_v['name'])}</code></summary>"
                + _diff_html(nt_v["description"], nt_d["description"])
                + "</details>"
            )

        # Developer details: full result JSON, full tools/list with
        # schemas, raw telemetry rows, mount paths, Inspector snippet.
        def _raw(label: str, data: Any) -> str:
            return (
                "<details class='dev'>"
                f"<summary>{html.escape(label)}</summary>"
                f"<pre>{html.escape(json.dumps(data, indent=2, ensure_ascii=False, default=str))}</pre>"
                "</details>"
            )

        dev_block = (
            "<details class='dev' open>"
            "<summary>Developer view: raw outputs, tools/list, MCP Inspector</summary>"
            f"<div class='kv' style='margin-top:0.6rem'>"
            f"<strong>Vulnerable mount:</strong> "
            f"<code>{html.escape(mcp_v_url)}</code><br>"
            f"<strong>Defended mount:</strong> "
            f"<code>{html.escape(mcp_d_url)}</code><br>"
            "<small><strong>Open in MCP Inspector:</strong> run "
            "<code>npx @modelcontextprotocol/inspector</code> locally "
            "and paste either URL above as a Streamable HTTP server."
            "</small>"
            "</div>"
            + _raw("DemoResult: vulnerable", result_v.model_dump())
            + _raw("DemoResult: defended", result_d.model_dump())
            + "<details><summary>tools/list (vulnerable)</summary>"
            + "".join(_format_tool(t) for t in tools_v)
            + "</details>"
            + "<details><summary>tools/list (defended)</summary>"
            + "".join(_format_tool(t) for t in tools_d)
            + "</details>"
            + _raw("telemetry: vulnerable", [e.model_dump() for e in events_v])
            + _raw("telemetry: defended", [e.model_dump() for e in events_d])
            + "</details>"
        )

        background_block = (
            f'<div class="intro context">'
            f'<div class="context-label">Background on this attack class</div>'
            f"{intro_paragraph}"
            f"</div>"
        )

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
            f"{summary_panel}"
            f"{diff_block}"
            '<div class="cols">'
            '<div class="col vuln">'
            "<h2>Vulnerable mode</h2>"
            f"{_result_pills(result_v)}"
            f"{outcome_v}"
            "</div>"
            '<div class="col def">'
            "<h2>Defended mode</h2>"
            f"{_result_pills(result_d)}"
            f"{outcome_d}"
            "</div>"
            "</div>"
            f"{background_block}"
            f"{dev_block}"
            "</body></html>"
        )
        return HTMLResponse(body)

    return router
