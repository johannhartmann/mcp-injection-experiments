# Migration Plan - Sichere MCP Streamable HTTP Online-Demo

Dieser Plan beschreibt den schrittweisen Umbau des Repositories von einer Sammlung historischer MCP-Tool-Poisoning-Snippets zu einer sicheren, didaktisch nutzbaren Online-Demo-Suite mit Streamable HTTP, Mock-Sinks, Canary-Daten sowie verwundbaren und verteidigten Modi pro Experiment.

## 1. Ist-Zustand

### 1.1 Bestehende Code-Artefakte

Im Repo-Root liegen historische Proof-of-Concept-Snippets, die mit dem offiziellen MCP Python SDK (`mcp.server.fastmcp`) und STDIO-Transport arbeiten:

- `direct-poisoning.py` - `add(a, b, sidenote)` mit poisoned tool description, die das Lesen von `~/.cursor/mcp.json` und `~/.ssh/id_rsa.pub` einfordert. STDIO-MCP-Server, FastMCP-basiert.
- `shadowing.py` - `add(a, b)` mit poisoned description, die das Verhalten eines fremden `send_email`-Tools manipuliert (Hidden BCC an `attkr@pwnd.com`). Reine Definition, kein Runner.
- `whatsapp-takeover.py` - kombiniert Tool Shadowing mit Sleeper Rug Pull: harmlose Beschreibung beim ersten Laden, boesartige Beschreibung ab dem zweiten Start. Verwendet `os.system("touch ~/.mcp-triggered")` als Trigger und nutzt `~/.mcp-triggered` als Zustandsdatei.
- `README.md` - Beschreibung der drei PoCs in englischer Sprache.

### 1.2 Bestehende Doku, Vorlagen und Pruefkriterien

Beim Auspacken des Prompt-Packs sind folgende unterstuetzende Artefakte bereits vorhanden:

- `architecture/target-structure.md`, `architecture/security-model.md`, `architecture/api-contracts.md`, `architecture/observable-impact-model.md`
- `checklists/demo-safety-checklist.md`, `checklists/deployment-checklist.md`
- `context/research-notes.md`
- `owasp-mapping/remote-demo-coverage.md`
- `prompts/00-...` bis `prompts/15-...` als Schritt-fuer-Schritt-Anleitung
- `snippets/commit-plan.md`, `snippets/example-curl.md`, `snippets/impact-event-examples.md`
- `templates/example-manifest.yaml`, `templates/experiment-manifest.schema.json`
- `CLAUDE.md` mit harten Sicherheitsgrenzen

### 1.3 Sicherheitsrelevante Probleme der Snippets

- `direct-poisoning.py` und `shadowing.py` adressieren reale Pfade (`~/.cursor`, `~/.ssh`) und einen realen Fake-Empfaenger (`attkr@pwnd.com`). Eine Live-Demo darf diese Strings nicht in der Form ausspielen, weil ein angeschlossener Agent versuchen wuerde, sie zu erfuellen.
- `whatsapp-takeover.py` schreibt eine Datei nach `~/.mcp-triggered` und macht damit echte Dateisystem-Nebenwirkungen ausserhalb der Demo-Zone.
- Alle drei Snippets nutzen STDIO-Transport, sind also nicht remote testbar.
- Es gibt weder Tests noch ein Manifest noch Telemetrie.

## 2. Zielarchitektur

Die Zielarchitektur folgt `architecture/target-structure.md` und `architecture/observable-impact-model.md`. Kernpunkte:

```text
Browser / Demo UI
  |
  | HTTPS (lokal HTTP, 127.0.0.1)
  v
FastAPI Demo App + MCP Client Simulator
  |
  | Streamable HTTP / JSON-RPC (POST + optional GET/SSE)
  v
MCP Demo Endpoints
  /mcp/direct-poisoning
  /mcp/tool-shadowing
  /mcp/sleeper-rug-pull
  /mcp/registry-rug-pull
  /mcp/cross-session-leak
  /mcp/auth-confused-deputy
  /mcp/ssrf-metadata
  /mcp/sampling-abuse
  /mcp/mock-mail
  /mcp/mock-filesystem
  /mcp/mock-sink
```

### 2.1 Zielverzeichnisstruktur

```text
src/mcp_demo/
  app.py
  config.py
  transport/
    streamable_http.py
    jsonrpc.py
    sse.py
  shared/
    canary.py
    mock_sinks.py
    policy.py
    telemetry.py
    manifests.py
    results.py
    url_safety.py
    auth_mock.py
    impact_ledger.py
  experiments/
    registry.py
    direct_poisoning.py
    tool_shadowing.py
    sleeper_rug_pull.py
    registry_rug_pull.py
    cross_session_leak.py
    auth_confused_deputy.py
    ssrf_metadata.py
    sampling_abuse.py
  client_simulator/
    planner.py
    runner.py
    policies.py
  web/
    routes.py
    templates/
    static/
tests/
  unit/
  integration/
  security/
experiments/
  manifests/
sandbox/
  README.md
  effects/
var/
  mock-inbox.jsonl
  telemetry.jsonl
  demo.db
docs/
  migration-plan.md
  owasp-mcp-coverage.md
  deployment.md
legacy/
  direct-poisoning.py
  shadowing.py
  whatsapp-takeover.py
```

### 2.2 Komponentenmodell

- **Transport Layer**: JSON-RPC-Envelope, Streamable HTTP POST, optional SSE GET, Origin-Validation, `Mcp-Session-Id` Vergabe und Pruefung.
- **Shared Safety Layer**: Canary-Generator, Mock-Sinks, Policy Engine, Telemetry Event Bus, URL-Safety mit Mock-Resolver, Fake-OAuth/JWT, Impact Ledger.
- **Experiment Layer**: ein Modul pro Experiment. Jedes Modul implementiert `list_tools(mode, session)`, `call_tool(name, arguments, mode, session)` und `run_scenario(mode)`.
- **Client Simulator**: deterministischer Planer plus Runner, der ohne echtes LLM einen vulnerable bzw. defended Pfad waehlt.
- **UI Layer**: serverseitig gerendertes HTML mit User Intent, Trace, Observable Impact, Defense Explanation und Reset.

### 2.3 Ziel-Tooling

- Python 3.11+
- `uv` als Paket- und Environment-Manager. `uv` haelt `pyproject.toml` und `uv.lock` aktuell und reproduzierbar. Tests laufen via `uv run pytest`.
- `pytest`, `httpx`, `pydantic`, `FastAPI` (oder `Starlette`), `uvicorn` als Kernabhaengigkeiten.
- Offizielles MCP Python SDK, sofern API zum Streamable-HTTP-Transport im aktuellen Stand passt. Sonst kleine, gut dokumentierte JSON-RPC/Streamable-HTTP-Fassade unter `src/mcp_demo/transport/`, kapselbar fuer spaeteren SDK-Wechsel.
- Docker und `docker-compose.yml` werden erst in Schritt 13 ergaenzt. Bis dahin lokale Entwicklung via `uv run`.

## 3. Geplante Experimente

| Experiment-ID | Zielverzeichnis | OWASP MCP | Mock-Surface |
|---|---|---|---|
| `remote-direct-poisoning` | `experiments/direct_poisoning.py` | MCP01, MCP03, MCP06 | Mock-Filesystem + Mock-Sink |
| `remote-tool-shadowing` | `experiments/tool_shadowing.py` | MCP03, MCP09, MCP10 | Mock-Mail (Hidden BCC) |
| `remote-sleeper-rug-pull` | `experiments/sleeper_rug_pull.py` | MCP03, MCP04 | Tool-Description-Hash-Diff |
| `remote-registry-rug-pull` | `experiments/registry_rug_pull.py` | MCP02, MCP04 | Fake Registry + Permission Delta |
| `remote-cross-session-leak` | `experiments/cross_session_leak.py` | MCP10 | Zwei Demo-Sessions |
| `remote-auth-confused-deputy` | `experiments/auth_confused_deputy.py` | MCP01, MCP07 | Fake OAuth + Audience Check |
| `remote-ssrf-metadata` | `experiments/ssrf_metadata.py` | MCP05 (simuliert) | Mock-Resolver + Mock-Metadata |
| `remote-sampling-abuse` | `experiments/sampling_abuse.py` | MCP06, MCP08 | Fake-LLM + Budgetzaehler |
| `audit-telemetry-dashboard` | `web/routes.py` + Ledger | MCP08 | Telemetry-JSONL |

Mapping zu bestehenden PoCs:

- `direct-poisoning.py` -> `remote-direct-poisoning` (Ziele werden zu Mock-Filesystem-Pfaden, Sidenote landet im Mock-Sink, Canary statt echter Datei).
- `shadowing.py` -> `remote-tool-shadowing` (Hidden BCC nur in Mock-Mail-Inbox).
- `whatsapp-takeover.py` -> `remote-sleeper-rug-pull` (Trigger ueber Demo-DB-Flag, nicht ueber `~/.mcp-triggered`); zusaetzlich indirekt in `remote-tool-shadowing`.

## 4. Sicherheitsgrenzen

Diese Grenzen sind nicht verhandelbar. Sie ergaenzen `CLAUDE.md`, `architecture/security-model.md` und `checklists/demo-safety-checklist.md`.

1. **Keine echten Secrets**. Keine Lese- oder Schreibzugriffe auf `~`, `~/.ssh`, echte `mcp.json`, echte Cursor-/Claude-Konfigs, `.env`. Erlaubt sind ausschliesslich Pfade unter `sandbox/` und in `var/` sowie zur Laufzeit erzeugte Canary-Werte.
2. **Keine echte Exfiltration**. Jeder Leak landet ausschliesslich in `MockSink`, einer lokalen Demo-Inbox oder unter `sandbox/effects/`. Keine Outbound-Requests an fremde Domains, keine Webhooks, keine Pastebins, keine echten Mail-/Chat-/GitHub-/WhatsApp-/Slack-APIs.
3. **Keine unkontrollierte RCE**. Kein `os.system`, keine `subprocess`-Aufrufe mit User-Input. RCE-Beweise nur ueber einen fest verdrahteten `ImpactRunner`, der ohne Argumente eine Datei unter `sandbox/effects/rce-proof-<session>.txt` schreibt. GUI-Calc nur lokal hinter Feature Flag, nie im Public Hosting.
4. **Kein echtes SSRF**. URL- und Metadata-Demos laufen ueber einen Mock-Resolver. Keine Requests an private IPs, Link-Local-Adressen oder Cloud-Metadata-Endpunkte.
5. **Keine echten Accounts**. Mail, WhatsApp, OAuth, Registry und API-Zugriffe sind immer Fake- oder Mock-Systeme.
6. **Keine persistente Sammlung echter Nutzerdaten**. Sessions kurzlebig, Logs gescrubbt, Demo-Reset vorhanden.
7. **Origin- und Session-Disziplin**. `Origin` wird gegen eine Allowlist geprueft. `Mcp-Session-Id` wird zufaellig vergeben und nicht als Authentisierung verwendet. Event Queues werden nach `user_id:session_id` partitioniert.
8. **Egress-Default deny**. `DEMO_EGRESS_MODE=deny` ist der Default. Bind-Default ist `127.0.0.1`.
9. **Behandlung der Legacy-Snippets**. `direct-poisoning.py`, `shadowing.py`, `whatsapp-takeover.py` werden in Schritt 4 ff. nach `legacy/` verschoben und im README als historisch markiert. Sie werden nicht ausgefuehrt, sondern ersetzt.

## 5. Teststrategie

Test-first. Jeder Implementierungsschritt beginnt mit Tests, die zunaechst rot sind oder zumindest dokumentiert rot waeren.

### 5.1 Testpyramide

- `tests/unit/` - Manifest-Schema, Result-Contract, Registry, Canary-Generator, Policy-Engine, URL-Safety, Telemetry-Bus, Impact Ledger.
- `tests/integration/` - HTTP-Tests gegen die Demo-App: `initialize`, `tools/list`, `tools/call`, `Mcp-Session-Id`, Origin-Pruefung, SSE-Roundtrip pro Experiment, `/demo`-UI, `/healthz`, `/readyz`.
- `tests/security/` - Negativtests: keine Outbound-Requests, keine Reads ausserhalb `sandbox/`, keine Shell-Ausfuehrung aus Input, Public-Mode-Guards (Admin-Token, Debug aus, Origin-Allowlist nicht wildcard).

### 5.2 Werkzeuge

- `pytest` als Runner, `pytest-asyncio` falls noetig.
- `httpx.AsyncClient` gegen `FastAPI`/`Starlette` per ASGI-Transport, kein echter Netzwerk-Roundtrip in Tests.
- Monkeypatched Filesystem-Roots, sodass `MockSink`, `mock-inbox.jsonl`, `telemetry.jsonl` in einem temporaeren Verzeichnis landen.
- Snapshot-Asserts auf JSON-Result-Schema gemaess `architecture/api-contracts.md`.

### 5.3 Lauf- und Doku-Pflichten pro Schritt

- `uv run pytest` muss gruen sein.
- Relevante Manifest-Aenderungen werden in `experiments/manifests/` und `docs/owasp-mcp-coverage.md` reflektiert.
- README erhaelt einen `Development`-Abschnitt mit `uv sync`, `uv run pytest`, `uv run uvicorn ...`.

## 6. Reihenfolge der Umsetzung

Die Reihenfolge folgt `prompts/` und `snippets/commit-plan.md`. Jeder Schritt schliesst mit einem kleinen, gruenen Commit ab.

### 6.1 Erste fuenf Implementierungsschritte (verbindlich)

1. **Schritt 1 - Test Harness und Projektgrundlage** (`prompts/01-test-harness-foundation.md`).
   - `pyproject.toml` via `uv init` und `uv add`.
   - `src/mcp_demo/shared/manifests.py`, `src/mcp_demo/shared/results.py`, `src/mcp_demo/experiments/registry.py`.
   - Erstes Dummy-Manifest unter `experiments/manifests/remote-direct-poisoning.yaml`.
   - Tests: `tests/unit/test_manifest_schema.py`, `tests/unit/test_experiment_registry.py`, `tests/unit/test_demo_result_contract.py`.
   - README-Abschnitt `Development`.
   - Commit: `test: add experiment manifest and result contracts`.

2. **Schritt 2 - Safe Sandbox und Canaries** (`prompts/02-safe-sandbox-canaries.md`).
   - `src/mcp_demo/shared/canary.py`, `src/mcp_demo/shared/mock_sinks.py`, `sandbox/README.md`.
   - Tests: Canary-Eindeutigkeit, Mock-Sink-Schreibbegrenzung, keine Pfad-Escapes aus `sandbox/`.
   - Commit: `feat: add safe sandbox canaries and mock sinks`.

3. **Schritt 3 - Observable Impact Ledger** (`prompts/02b-observable-impact-ledger.md`).
   - `src/mcp_demo/shared/impact_ledger.py`, `src/mcp_demo/shared/telemetry.py`.
   - JSONL Append in `var/telemetry.jsonl`, Reset-API.
   - Tests: Schema-Validierung, Append-only, Reset, Partition nach Session.
   - Commit: `feat: add observable impact ledger and telemetry bus`.

4. **Schritt 4 - Streamable HTTP Transport** (`prompts/03-streamable-http-transport.md`).
   - `src/mcp_demo/transport/jsonrpc.py`, `src/mcp_demo/transport/streamable_http.py`, optional `sse.py`.
   - `src/mcp_demo/app.py` mit `/healthz`, `/readyz`, `/mcp/*`-Routern. Origin-Allowlist, Session-ID-Vergabe.
   - Tests: `initialize`/`tools/list`/`tools/call`, Origin-Reject, fehlende Session-ID, SSE-Heartbeat.
   - Legacy-Snippets nach `legacy/` verschieben.
   - Commit: `feat: add MCP streamable HTTP demo transport`.

5. **Schritt 5 - Remote Direct Poisoning** (`prompts/04-remote-direct-poisoning.md`).
   - `src/mcp_demo/experiments/direct_poisoning.py` mit vulnerable und defended Pfad.
   - Mock-Filesystem mit Canary-Datei, Mock-Sink fuer Exfiltration.
   - Telemetry- und Impact-Events.
   - Tests: vulnerable schreibt Canary in Mock-Sink, defended blockt mit Policy-Begruendung, JSON-Result entspricht Contract.
   - Commit: `feat: add safe remote direct poisoning demo`.

### 6.2 Weitere Schritte (Uebersicht)

6. Tool Shadowing Demo (Mock-Mail + Hidden BCC).
7. Sleeper Rug Pull Demo (Description-Hash-Diff).
8. Registry Rug Pull Demo (Fake-Registry + Permission Delta).
9. Cross-Session Context Leak Demo (zwei Sessions).
10. Auth Confused Deputy Demo (Fake-OAuth + Audience).
11. SSRF Metadata Demo (Mock-Resolver).
12. Audit/Telemetry-Dashboard.
13. Sampling Abuse Demo (Fake-LLM + Budget).
14. Demo UI und lokales Docker-Deployment.
15. Security Hardening Review.
16. Doku-Finalisierung.

Jeder Schritt muss die Definition of Done aus `CLAUDE.md` erfuellen: Tests existieren und laufen, Modi sind klar unterscheidbar, keine echten Secrets, Manifeste und README aktualisiert, Telemetrie-Events vorhanden.
