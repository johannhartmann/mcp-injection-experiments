# Prompt 02 - Sandbox, Canaries und Mock-Sinks

```text
Arbeite test-first.

Ziel: Erstelle die sicheren Grundbausteine, die alle Angriffsdemos verwenden: Canary-Daten, Mock-Filesystem, Mock-Sink, Network Guard.

Sicherheitsgrenzen:
- Keine echten Dateien ausserhalb von `sandbox/` lesen.
- Kein echter Outbound HTTP Request.
- Kein Zugriff auf Home-Verzeichnis, `.env`, SSH, echte MCP-Konfigs.

Erst Tests schreiben:
1. `tests/unit/test_canary.py`
   - Canary-Werte sind eindeutig pro Session.
   - Canary-Werte enthalten Experiment-ID.
   - Canary-Werte sind leicht in Logs zu erkennen.
2. `tests/security/test_mock_filesystem_boundaries.py`
   - Lesen von `sandbox/demo-secret.txt` ist erlaubt.
   - Lesen von `../`, `~/.ssh/id_rsa`, `.env` wird abgelehnt.
   - Symlink-Ausbruch aus `sandbox/` wird abgelehnt, falls Symlink-Support existiert.
3. `tests/unit/test_mock_sink.py`
   - MockSink speichert Events im Speicher.
   - MockSink markiert Canary-Leak als `secret_exfiltrated=true`.
   - MockSink scrubbt offensichtliche Token-Muster in Logs.
4. `tests/security/test_network_guard.py`
   - Outbound ist default `deny`.
   - Allowlist akzeptiert nur explizit konfigurierte Demo-Hosts.

Dann implementieren:
- `src/mcp_demo/shared/canary.py`
- `src/mcp_demo/shared/mock_filesystem.py`
- `src/mcp_demo/shared/mock_sinks.py`
- `src/mcp_demo/shared/network_guard.py`
- `sandbox/README.md`
- `sandbox/demo-secret.txt` mit einem offensichtlichen Demo-Canary, keinem echten Secret.

Akzeptanzkriterien:
- Alle Tests laufen.
- Der Mock-Filesystem-Code nutzt Pfadnormalisierung und prueft, dass final aufgeloeste Pfade unter `sandbox/` liegen.
- Kein Test oder Code greift auf echte Benutzerpfade zu.
- README beschreibt, dass nur Canary-Daten verwendet werden.
```

Erwarteter Commit:

```text
feat: add safe sandbox canaries and mock sinks
```
