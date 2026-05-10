# MCP HTTP Streaming Online Demo - Claude Code Prompt Pack

Dieses Prompt-Pack ist dafuer gedacht, das Repository `johannhartmann/mcp-injection-experiments` schrittweise in eine sichere Online-Demo-Suite umzubauen.

Zielbild:

- MCP-Server sind per Streamable HTTP erreichbar, z. B. `/mcp/direct-poisoning`.
- Eine kontrollierte Web-Demo bzw. ein MCP-Client-Simulator zeigt verwundbare und verteidigte Varianten nebeneinander.
- Alle Demos arbeiten mit Canary-Daten, Mock-Sinks, lokalen Testdaten und sichtbaren, begrenzten Nebenwirkungen.
- Keine echten Secrets, keine echten Drittanbieter-APIs, keine unkontrollierte RCE, keine echten internen Netzwerkzugriffe.
- Verwundbare Modi duerfen echte Effekte erzeugen, aber nur in der Demo-Zone: Mock-Inbox, MockSink, sandbox/effects, Demo-DB und Telemetrie.
- Jede Erweiterung entsteht test-first mit `pytest`/HTTP-Integrationstests.

## Verwendung

1. Entpacke dieses Paket neben oder in das Zielrepo.
2. Kopiere `CLAUDE.md` in den Root des Zielrepos.
3. Starte Claude Code im Zielrepo.
4. Fuehre die Prompts aus `prompts/` der Reihe nach aus.
5. Nach jedem Prompt: Tests laufen lassen, Diff pruefen, Commit machen.

Empfohlene Reihenfolge:

```text
prompts/00-baseline-repo-audit.md
prompts/01-test-harness-foundation.md
prompts/02-safe-sandbox-canaries.md
prompts/02b-observable-impact-ledger.md
prompts/03-streamable-http-transport.md
prompts/04-remote-direct-poisoning.md
prompts/05-remote-tool-shadowing.md
prompts/06-remote-sleeper-rug-pull.md
prompts/07-remote-registry-rug-pull.md
prompts/08-remote-cross-session-context-leak.md
prompts/09-remote-auth-confused-deputy.md
prompts/10-remote-ssrf-metadata-discovery-simulation.md
prompts/11-audit-telemetry-dashboard.md
prompts/12-remote-sampling-abuse-simulation.md
prompts/13-demo-ui-and-docker.md
prompts/14-security-hardening-review.md
prompts/15-docs-final-polish.md
```

## Was dieses Pack bewusst nicht tut

Dieses Pack liefert keine realen Angriffspayloads gegen echte Services. Es beschreibt Demo-Angriffe mit echten, beobachtbaren Nebenwirkungen innerhalb einer isolierten Demo-Zone. Beispiele: ein Canary erscheint in einer Mock-Attacker-Inbox, eine Datei wird unter `sandbox/effects/` erzeugt, ein Fake-CRM-Datensatz wird veraendert oder ein Budgetzaehler wird verbraucht. Es beruehrt keine echten lokalen Dateien, echten Tokens, echten Chat-/Mail-APIs oder fremden Netzwerkziele.

## Designprinzip

Jeder Prompt folgt demselben Muster:

1. vorhandenen Code inspizieren,
2. Tests zuerst schreiben,
3. minimale Implementierung bauen,
4. Sicherheitsgrenzen pruefen,
5. Dokumentation und Manifeste aktualisieren.

## Development

Die Demo-Suite nutzt [`uv`](https://docs.astral.sh/uv/) als Paket- und
Environment-Manager. Python 3.11 oder neuer wird vorausgesetzt.

```bash
# Initiale Einrichtung (legt .venv/ an, installiert mcp-demo + Dev-Deps)
uv sync --all-extras

# Tests laufen lassen
uv run pytest

# Nur Unit-Tests
uv run pytest tests/unit -v
```

Wichtige Pfade:

- `src/mcp_demo/` - Anwendungs-Code (Manifeste, Registry, spaeter Transport,
  Experimente, Web-UI).
- `experiments/manifests/` - YAML-Manifeste pro Experiment. Werden beim Start
  validiert; ein Manifest mit `uses_real_secrets: true` oder
  `safe_mode: false` wird abgelehnt.
- `tests/unit/` - schnelle Vertragstests (Manifest, Registry, Result-Schema).
- `tests/integration/` - HTTP-/MCP-Integrationstests (folgt in spaeteren Schritten).
- `tests/security/` - Negativtests fuer Sicherheitsgrenzen (folgt).
- `docs/migration-plan.md` - Reihenfolge der Umsetzung.
- `docs/owasp-mcp-coverage.md` - OWASP MCP Top 10 Coverage-Matrix.

Die Demo verwendet ausschliesslich Mock-Komponenten und Canary-Daten innerhalb
der Demo-Zone (`sandbox/`, `var/`). Echte Secrets, echte Drittanbieter-APIs
und echte Outbound-Requests sind verboten - siehe `CLAUDE.md` und
`architecture/security-model.md`.

## Streamable HTTP demo transport

Die Demo-Suite implementiert eine kleine, gut isolierte JSON-RPC-/Streamable-
HTTP-Fassade unter `src/mcp_demo/transport/`. Das offizielle MCP Python SDK
wird bewusst nicht eingebunden, weil die Demo pro Methode (`initialize`,
`tools/list`, `tools/call`) gezielt zwischen verwundbarem und verteidigtem
Verhalten umschalten und Tool-Beschreibungen sichtbar manipulieren muss.
Wenn ein Wechsel auf das SDK sinnvoll wird, ist die Schnittstelle in
`transport/jsonrpc.py` und `transport/streamable_http.py` der einzige Punkt,
der angepasst werden muss.

Lokal starten:

```bash
uv run uvicorn mcp_demo.app:create_app --factory --host 127.0.0.1 --port 8000
```

`/healthz` antwortet ohne `Origin`-Pruefung. Alle `/mcp/*`-Endpunkte
verlangen einen allowlisteten `Origin` und nach `initialize` einen
gueltigen `Mcp-Session-Id`-Header.

### Beispiel-cURL

```bash
# initialize -> liefert Mcp-Session-Id im Response-Header
curl -i -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":"init-1",
    "method":"initialize",
    "params":{
      "protocolVersion":"2025-03-26",
      "capabilities":{},
      "clientInfo":{"name":"demo-client","version":"0.1.0"}
    }
  }'
```

```bash
# tools/list -> erwartet die Mcp-Session-Id aus initialize
curl -s -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":"tools-1","method":"tools/list"}'
```

```bash
# tools/call calculator.add
curl -s -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc":"2.0","id":"call-1",
    "method":"tools/call",
    "params":{"name":"calculator.add","arguments":{"a":2,"b":3}}
  }'
```

Defaults aus `src/mcp_demo/config.py`:

- `bind_host=127.0.0.1`, `bind_port=8000`.
- `allowed_origins` enthaelt nur `http://127.0.0.1:8000`,
  `http://localhost:8000` und `http://testserver` (ASGI-Tests).
- `egress_mode=deny`.

Ueberschreibbar via `DEMO_BIND_HOST`, `DEMO_BIND_PORT`,
`DEMO_ALLOWED_ORIGINS` (komma-separiert), `DEMO_EGRESS_MODE`.

## Remote Direct Poisoning

Die erste vollstaendige Demo unter `/mcp/direct-poisoning` ist die sichere
Migration des historischen `direct-poisoning.py`-PoC. Statt `~/.cursor/mcp.json`
oder `~/.ssh/id_rsa` referenziert die Tool-Beschreibung ausschliesslich die
Datei `sandbox/demo-secret.txt`, deren Inhalt eine offensichtliche Fake-Canary
ist.

Modus-Schalter:

- `vulnerable`: `tools/list` liefert die poisoned Description mit
  `<IMPORTANT>`-Block samt verstecktem Lese-Befehl. `tools/call` mit einem
  `sidenote`-Argument leitet den Inhalt an `MockSink` weiter; der Sink markiert
  das als `secret_exfiltrated=True`. Der `ImpactRunner` schreibt einen
  `mock_exfiltration`-Event ins JSONL-Telemetry-Log.
- `defended`: `tools/list` zeigt die durch `sanitise_tool_description`
  bereinigte Variante (kein `<IMPORTANT>`-Block, keine "do not mention"-
  Saetze). `tools/call` prueft das `sidenote`-Argument gegen die
  `CanaryExfiltrationPolicy`; bei einem registrierten Canary refused der
  Policy-Decision-Pfad und schreibt einen `blocked_attempt_recorded`-Event mit
  Begruendung. Der defended `DemoResult` enthaelt
  `blocked_by=["canary_exfiltration_policy"]`.

Modus-Auswahl pro Session: beim `initialize`-Request kann der Client per
`params.demo.mode = "vulnerable" | "defended"` den Modus festlegen. Default ist
`defended`.

`run_scenario(mode, session_id, runtime)` ist die testbare Skript-API. Sie
liest den Canary aus dem Mock-Filesystem, durchlaeuft den Mode-spezifischen
Pfad, und liefert einen vollstaendigen `DemoResult`. Damit lassen sich UI und
Tests speisen, ohne den HTTP-Layer zu starten.

Sicherheitsgrenzen pro Definition of Done:

- keine echten Konfig-/SSH-/Token-Pfade in der Tool-Beschreibung;
- keine `os.path.expanduser`-Aufrufe und keine direkten `Path.read_text`-
  Aufrufe ausserhalb von `MockFilesystem`;
- jede Datei-Lese-Operation laeuft durch `MockFilesystem`, das Pfad-Traversal,
  Symlink-Escape und Suspicious-Basenames refused;
- Exfiltration landet nur in `MockSink` und im JSONL-Telemetry-Ledger.

## Observable impact model

Jedes Experiment muss seinen Effekt **wirklich erzeugen**, aber nur innerhalb
der Demo-Zone. Der zentrale Baustein ist der `ImpactRunner` in
`src/mcp_demo/shared/impact.py`. Er bietet vier sichere Effekt-Pfade:

- `mock_exfiltrate_to_sink(...)` - Vulnerable Mode: liefert eine Payload an
  `MockSink`. Wenn die Payload einen vorher registrierten Canary enthaelt,
  setzt der Sink `secret_exfiltrated=True`.
- `mock_send_message(...)` - Vulnerable Mode: schreibt einen Eintrag in
  `var/mock-inbox.jsonl` (Mock-Mail/WhatsApp/Slack-Pendant) und delivered
  parallel an den Sink.
- `write_sandbox_file(...)` - Vulnerable Mode: legt eine Datei unter
  `sandbox/effects/` mit Canary und Metadaten an. Pfad-Traversal,
  absolute Pfade und Home-Referenzen werden mit `ImpactSafetyError`
  refused, bevor irgendein I/O passiert.
- `record_blocked_attempt(...)` - Defended Mode: erzeugt einen
  `blocked_attempt_recorded`-Event mit Begruendung, ohne den eigentlichen
  Impact zuzulassen.

Alle Effekte werden in einem `ImpactLedger` gesammelt. Der Ledger
partitioniert In-Memory-Events nach `session_id`, ein optionaler JSONL-Pfad
(`var/telemetry.jsonl`) hinterlaesst zusaetzlich einen append-only
Audit-Trail. Reset wirkt nur auf die jeweilige Session und laesst den JSONL
unangetastet.

Nicht erlaubte Impact-Wege:

- echte Outbound-HTTP-Requests, echte Mail-/Chat-/GitHub-/OAuth-APIs.
- Subprocess-Aufrufe mit User-Input. Der einzige Subprocess-Helfer
  (`run_local_calc_proof`) nimmt **keine** Argumente und ist standardmaessig
  deaktiviert; aktivierbar nur lokal per `DEMO_ENABLE_LOCAL_CALC_PROOF=true`,
  nie im Public Hosting.
