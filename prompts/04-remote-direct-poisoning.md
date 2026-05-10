# Prompt 04 - Remote Direct Poisoning als sichere Canary-Demo

```text
Arbeite test-first.

Ziel: Migriere das historische Direct-Poisoning-Beispiel in eine sichere Remote-Demo unter `/mcp/direct-poisoning`. Die Demo darf nur Canary-Daten aus der Sandbox verwenden und nur an MockSink schreiben.

Sicherheitsgrenzen:
- Keine echten SSH Keys, keine echten MCP Configs, keine Home-Verzeichnisse.
- Keine echte Exfiltration.
- Tool-Metadaten duerfen nur Demo-/Canary-Ziele adressieren.

Erst Tests schreiben:
1. `tests/integration/test_remote_direct_poisoning.py`
   - `tools/list` zeigt ein harmlos wirkendes Demo-Tool, z. B. `calculator.add`.
   - Im Mode `vulnerable` fuehrt das Szenario dazu, dass ein Canary aus MockFilesystem in MockSink landet.
   - Im Mode `defended` wird derselbe Datenfluss blockiert.
   - Defended Result enthaelt `blocked_by` mit passender Policy.
2. `tests/security/test_direct_poisoning_no_real_paths.py`
   - Die Demo enthaelt keine Pfade wie `~/.ssh`, echte `.env`, echte Client-Konfigs.
   - Tool-Implementierung nutzt nur `MockFilesystem`.
3. `tests/unit/test_tool_description_linter.py`
   - Linter markiert Tool-Beschreibungen, die versteckte Datenflussanweisungen enthalten.
   - Linter blockiert nicht harmlose Tool-Beschreibungen.

Dann implementieren:
- `src/mcp_demo/experiments/direct_poisoning.py`
- Policy in `src/mcp_demo/shared/policy.py`
- Manifest `experiments/manifests/remote-direct-poisoning.yaml`
- UI/Runner hook, falls Demo-Runner existiert.

Akzeptanzkriterien:
- Vulnerable Mode zeigt kontrollierten Canary-Leak in MockSink.
- Defended Mode blockiert und erklaert den Block.
- Keine realen Pfade oder echten Secrets im Code.
- README erhaelt Abschnitt `Remote Direct Poisoning`.
```

Erwarteter Commit:

```text
feat: add safe remote direct poisoning demo
```


## Observable Impact Requirement

Vulnerable mode must create a real demo impact: write the session Canary to `MockSink` and persist an artifact under `var/mock-inbox.jsonl` or `sandbox/effects/direct-poisoning-<session>.json`. The UI must show: user asked for a benign action, tool metadata caused hidden dataflow, Canary reached attacker sink.

Defended mode must block the same dataflow and persist `blocked_attempt_recorded` with the blocking rule.
