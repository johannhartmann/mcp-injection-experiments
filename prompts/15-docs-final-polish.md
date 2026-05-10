# Prompt 15 - Finale Dokumentation und Demo-Skript

```text
Ziel: Erstelle eine nutzbare Abschlussdokumentation fuer Entwickler, Demo-Gaeste und Security Reviewer.

Aufgaben:
1. Aktualisiere `README.md`:
   - Was ist die Demo?
   - Safety Model.
   - Quickstart lokal.
   - Docker Quickstart.
   - MCP Streamable HTTP Beispiele.
   - Experimente und OWASP-Mapping.
   - Vulnerable vs. Defended Modus.
2. Erstelle `docs/demo-script.md`:
   - 15-Minuten Demo-Ablauf.
   - 30-Minuten Deep-Dive.
   - Welche Fragen typischerweise kommen.
   - Was nicht live gezeigt wird und warum.
3. Erstelle `docs/api.md`:
   - `/mcp/...` Endpunkte.
   - `/demo/run/...` Endpunkte.
   - `/demo/events`.
4. Erstelle `docs/operations.md`:
   - sichere Defaults,
   - Public Mode,
   - Reset,
   - Logging,
   - Rate Limits,
   - Troubleshooting.
5. Pruefe alle Links, Kommandos und Testbefehle.

Akzeptanzkriterien:
- Neue Nutzer koennen lokal starten, ohne Code zu lesen.
- Security Reviewer verstehen, warum keine echten Secrets/Angriffe enthalten sind.
- `pytest` laeuft.
- README listet alle Experimente mit Status.
```

Erwarteter Commit:

```text
docs: finalize online MCP demo documentation
```
