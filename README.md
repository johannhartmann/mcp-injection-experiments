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
