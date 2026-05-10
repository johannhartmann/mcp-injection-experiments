"""Landing page rendered at ``GET /``.

A self-contained HTML explanation that introduces MCP, the demo's
vulnerable-vs-defended model, the safety boundaries, the two HTTP
surfaces (real Streamable-HTTP MCP endpoints under
``/mcp/<id>/<mode>/`` and the dashboard JSON API under ``/demo/...``)
and the operational entry points (`/demo`, `/demo/events`,
`/healthz`, `/readyz`).

The page is server-rendered, has no external CDN dependency and runs
the same Origin allowlist as the MCP and dashboard surfaces (the
landing page itself does not require a matching Origin so a fresh
visitor in a browser can read it).
"""

from __future__ import annotations

from mcp_demo.experiments.registry import ExperimentRegistry


_STYLE = """
:root { color-scheme: light dark; }
body { font-family: system-ui, sans-serif; max-width: 1100px; margin: 1.5rem auto;
       padding: 0 1rem; line-height: 1.5; }
h1 { margin-top: 0; }
.hero { padding: 1.5rem; border-radius: 8px; background: #f4f4f7;
        border: 1px solid #ddd; margin-bottom: 2rem; }
.hero p:first-of-type { font-size: 1.05rem; }
.warn { padding: 0.8rem 1rem; border-left: 4px solid #d33; background: #fdf3f3;
        margin-bottom: 1.5rem; font-size: 0.95rem; }
section { margin-bottom: 2rem; }
section h2 { border-bottom: 1px solid #ccc; padding-bottom: 0.3rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { border: 1px solid #ddd; padding: 0.4rem 0.5rem; text-align: left;
         vertical-align: top; }
th { background: #f3f3f3; }
code { background: rgba(0,0,0,0.06); padding: 0 0.25rem; border-radius: 3px; }
pre { background: #f7f7fa; border: 1px solid #ddd; padding: 0.7rem;
      overflow-x: auto; font-size: 0.85rem; }
ul.compact { margin: 0.3rem 0 0 1.2rem; }
.badge { display: inline-block; padding: 0.05rem 0.4rem; font-size: 0.75rem;
         border-radius: 3px; background: #e7e7ea; margin-left: 0.4rem;
         vertical-align: middle; }
.badge.green { background: #d6f3d8; color: #1e5722; }
.badge.warn { background: #fde6c1; color: #804600; }
@media (prefers-color-scheme: dark) {
  body { background: #15161a; color: #ddd; }
  .hero { background: #1f2128; border-color: #2c2e36; }
  .warn { background: #3a1212; border-left-color: #ff6b6b; }
  th { background: #21232a; }
  th, td { border-color: #2c2e36; }
  pre { background: #1c1d24; border-color: #2c2e36; }
  code { background: rgba(255,255,255,0.08); }
  .badge { background: #2c2e36; color: #c8c8d0; }
  .badge.green { background: #1d3a23; color: #a4d9ad; }
  .badge.warn { background: #3a2c12; color: #f0c178; }
  a { color: #8bb6ff; }
}
""".strip()


_INTRO = """\
<p>This is a teaching-focused implementation of the
<a href="https://modelcontextprotocol.io/" target="_blank"
rel="noopener">Model Context Protocol</a> with seventeen exploit demos
plus eight Agent-Trap scenarios. Every experiment ships in two
explicitly-modeled modes:</p>
<ul class="compact">
  <li><strong>vulnerable</strong> &mdash; produces a real, bounded
  artefact in the demo zone (mock-inbox JSONL, mock-GitHub PR comment,
  sandbox/effects file, telemetry event). Never an outbound HTTP
  request, never a real account, never a real secret.</li>
  <li><strong>defended</strong> &mdash; runs the same flow through a
  named policy that refuses the unsafe step and persists a structured
  block event with the rule id and reason.</li>
</ul>
<p>The demo never speaks to a real LLM, never speaks to a real
third-party API, never executes user-controlled shell input.</p>
""".strip()


_SAFETY_BLOCK = """\
<div class="warn">
  <strong>Safety model.</strong> All effects stay inside
  <code>var/</code> and <code>sandbox/effects/</code>. Outbound HTTP is
  denied by default; the URL classifier blocks loopback, link-local,
  private and metadata addresses. <code>MockMailServer</code> only
  accepts the reserved <code>.example</code> TLD. <code>FAKEJWT</code>
  tokens are intentionally non-cryptographic. Public Mode refuses to
  start unless the operator overrides
  <code>DEMO_ADMIN_TOKEN</code> and configures a non-wildcard origin
  allowlist. See
  <a href="https://github.com/johannhartmann/mcp-injection-experiments/blob/main/docs/security-review.md"
     target="_blank" rel="noopener"><code>docs/security-review.md</code></a>
  for the full review.
</div>
""".strip()


def _experiment_rows(registry: ExperimentRegistry) -> str:
    rows: list[str] = []
    for manifest in registry.all():
        owasp = ", ".join(manifest.owasp) or "&mdash;"
        traps = ", ".join(manifest.agent_traps) or "&mdash;"
        surfaces = ", ".join(manifest.mcp_surfaces) or "&mdash;"
        phase_badge = (
            '<span class="badge green">expansion-2025-2026</span>'
            if manifest.phase == "expansion-2025-2026"
            else '<span class="badge">baseline</span>'
        )
        rows.append(
            "<tr>"
            f"<td><code>{manifest.id}</code>{phase_badge}</td>"
            f"<td>{manifest.title}</td>"
            f"<td>{owasp}</td>"
            f"<td>{traps}</td>"
            f"<td>{surfaces}</td>"
            "</tr>"
        )
    return "".join(rows)


def render_landing_page(
    *,
    registry: ExperimentRegistry,
    allowed_origins: tuple[str, ...],
    public_mode: bool,
) -> str:
    mode_label = (
        '<span class="badge warn">public mode</span>'
        if public_mode
        else '<span class="badge">local mode</span>'
    )
    origins_block = ", ".join(f"<code>{o}</code>" for o in allowed_origins) or "&mdash;"
    rows = _experiment_rows(registry)

    return (
        "<!doctype html><html><head>"
        "<meta charset=\"utf-8\">"
        "<title>MCP Injection Experiments &mdash; Demo Server</title>"
        f"<style>{_STYLE}</style>"
        "</head><body>"
        f"<h1>MCP Injection Experiments {mode_label}</h1>"
        f"{_SAFETY_BLOCK}"
        f"<div class='hero'>{_INTRO}</div>"

        "<section><h2>Two HTTP surfaces</h2>"
        "<p>Each experiment is reachable through two HTTP surfaces. Both"
        " enforce the Origin allowlist; the MCP surface additionally runs"
        " FastMCP&apos;s DNS-rebinding protection.</p>"
        "<table><thead><tr>"
        "<th>Surface</th><th>What it speaks</th><th>Path</th>"
        "</tr></thead><tbody>"
        "<tr>"
        "<td><strong>Real MCP</strong> (Streamable HTTP)</td>"
        "<td>Official <code>mcp</code> Python SDK on the server side. "
        "JSON-RPC&nbsp;2.0 over HTTP+SSE with <code>initialize</code>, "
        "<code>tools/list</code>, <code>tools/call</code>, and the "
        "<code>Mcp-Session-Id</code> handshake.</td>"
        "<td><code>/mcp/&lt;experiment&gt;/&lt;mode&gt;/</code></td>"
        "</tr>"
        "<tr>"
        "<td><strong>Demo dashboard</strong> (JSON)</td>"
        "<td>Convenience POST that drives <code>run_scenario</code> and "
        "returns the full <code>DemoResult</code> body. Used by the "
        "<a href='/demo'>/demo</a> UI and by external scripts.</td>"
        "<td><code>POST /demo/scenario/&lt;experiment&gt;</code></td>"
        "</tr>"
        "</tbody></table>"
        "<p>cURL the real MCP endpoint:</p>"
        "<pre>"
        "curl -i \\\n"
        "  -H 'Origin: http://127.0.0.1:8000' \\\n"
        "  -H 'Accept: application/json, text/event-stream' \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
        "\"params\":{\"protocolVersion\":\"2025-06-18\","
        "\"capabilities\":{},\"clientInfo\":"
        "{\"name\":\"demo-client\",\"version\":\"0.0.1\"}}}' \\\n"
        "  http://127.0.0.1:8000/mcp/direct-poisoning/vulnerable/"
        "</pre>"
        "<p>Or with the official Python client:</p>"
        "<pre>"
        "from mcp.client.session import ClientSession\n"
        "from mcp.client.streamable_http import streamable_http_client\n"
        "\n"
        "async with streamable_http_client(\n"
        "    'http://127.0.0.1:8000/mcp/direct-poisoning/vulnerable/'\n"
        ") as (read, write, _):\n"
        "    async with ClientSession(read, write) as session:\n"
        "        await session.initialize()\n"
        "        tools = await session.list_tools()"
        "</pre>"
        "</section>"

        "<section><h2>Experiments</h2>"
        f"<p>{len(registry)} experiments registered. The cards on "
        "<a href='/demo'>/demo</a> let you trigger any of them with one "
        "click; the timeline at <a href='/demo/events'>/demo/events</a> "
        "shows the structured impact ledger across runs.</p>"
        "<table><thead><tr>"
        "<th>id</th><th>title</th><th>OWASP</th><th>Agent Traps</th>"
        "<th>MCP surfaces</th>"
        "</tr></thead><tbody>"
        f"{rows}"
        "</tbody></table>"
        "</section>"

        "<section><h2>Operational endpoints</h2>"
        "<table><thead><tr>"
        "<th>Path</th><th>Purpose</th>"
        "</tr></thead><tbody>"
        "<tr><td><a href='/healthz'><code>GET /healthz</code></a></td>"
        "<td>liveness probe (no Origin check)</td></tr>"
        "<tr><td><a href='/readyz'><code>GET /readyz</code></a></td>"
        "<td>readiness probe; lists registered experiments</td></tr>"
        "<tr><td><a href='/demo'><code>GET /demo</code></a></td>"
        "<td>HTML dashboard with one card per experiment</td></tr>"
        "<tr><td><a href='/demo/events'><code>GET /demo/events</code></a></td>"
        "<td>telemetry timeline (JSON or HTML)</td></tr>"
        "<tr><td><code>POST /demo/reset</code></td>"
        "<td>admin-token-gated per-session reset</td></tr>"
        "</tbody></table>"
        f"<p>Allowlisted Origins: {origins_block}</p>"
        "</section>"

        "<section><h2>Documentation</h2>"
        "<ul class='compact'>"
        "<li><a href='https://github.com/johannhartmann/mcp-injection-experiments/blob/main/README.md'"
        " target='_blank' rel='noopener'>README &mdash; project overview</a></li>"
        "<li><a href='https://github.com/johannhartmann/mcp-injection-experiments/blob/main/docs/api.md'"
        " target='_blank' rel='noopener'>docs/api.md &mdash; HTTP API reference</a></li>"
        "<li><a href='https://github.com/johannhartmann/mcp-injection-experiments/blob/main/docs/operations.md'"
        " target='_blank' rel='noopener'>docs/operations.md &mdash; defaults, public mode, troubleshooting</a></li>"
        "<li><a href='https://github.com/johannhartmann/mcp-injection-experiments/blob/main/docs/security-review.md'"
        " target='_blank' rel='noopener'>docs/security-review.md &mdash; security review with residual risks</a></li>"
        "<li><a href='https://github.com/johannhartmann/mcp-injection-experiments/blob/main/docs/exploit-catalog-2025-2026.md'"
        " target='_blank' rel='noopener'>docs/exploit-catalog-2025-2026.md &mdash; expansion catalog</a></li>"
        "<li><a href='https://github.com/johannhartmann/mcp-injection-experiments/blob/main/docs/agent-traps-mcp-mapping.md'"
        " target='_blank' rel='noopener'>docs/agent-traps-mcp-mapping.md &mdash; trap-to-MCP mapping</a></li>"
        "</ul>"
        "</section>"

        "</body></html>"
    )
