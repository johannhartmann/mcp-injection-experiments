# Prompt 02b - Observable Impact Ledger

```text
Arbeite test-first.

Ziel: Ergaenze die Demo um echte, begrenzte Nebenwirkungen, damit Nutzer erkennen, dass ein Exploit wirklich eine Wirkung hatte. Die Nebenwirkungen duerfen nur innerhalb der Demo-Zone entstehen.

Konzept:
- Vulnerable Mode: erzeugt einen echten Demo-Impact.
- Defended Mode: verhindert denselben Impact und erzeugt einen echten Block-Event.
- Alle Impacts sind Canary-/Fake-Daten und werden in UI, Telemetrie und Demo-Artefakt sichtbar.

Erlaubte Impact-Ziele:
- `MockSink` im Speicher plus JSONL-Persistenz.
- `var/mock-inbox.jsonl`.
- `var/demo.db` oder einfache JSONL-Dateien, falls SQLite noch nicht eingefuehrt ist.
- `sandbox/effects/`.

Nicht erlaubt:
- echte Netzwerke, echte Konten, echte Secrets, echte User-Dateien.
- beliebige Shell-Ausfuehrung aus User-Input.
- beliebige Outbound-URLs.

Erst Tests schreiben:

1. `tests/unit/test_impact_events.py`
   - `ImpactEvent` verlangt `experiment`, `mode`, `impact_type`, `actor`, `target`, `policy_decision`.
   - `impact_type` akzeptiert nur erlaubte Werte: `mock_exfiltration`, `mock_message_sent`, `sandbox_file_written`, `session_leak_visible`, `permission_change_applied`, `budget_consumed`, `blocked_attempt_recorded`.
   - Events koennen als JSON serialisiert werden.

2. `tests/unit/test_impact_ledger.py`
   - Ledger speichert Events pro Session.
   - Ledger kann Events nach Experiment und Session filtern.
   - Ledger schreibt optional JSONL unter `var/telemetry.jsonl`.
   - Reset loescht nur Events der Demo-Session.

3. `tests/security/test_impact_boundaries.py`
   - Dateien duerfen nur unter `sandbox/effects/` geschrieben werden.
   - Pfad-Traversal wird blockiert.
   - Ein Impact darf kein Ziel ausserhalb der Allowlist verwenden.

4. `tests/unit/test_impact_runner.py`
   - `ImpactRunner.write_sandbox_file()` schreibt eine Datei mit Canary und Metadaten.
   - `ImpactRunner.mock_send_message()` erzeugt einen echten Mock-Inbox-Eintrag.
   - `ImpactRunner.record_blocked_attempt()` erzeugt einen Block-Event.
   - Optionaler `run_local_calc_proof()` ist per Default deaktiviert und akzeptiert keine User-Argumente.

Dann implementieren:

- `src/mcp_demo/shared/impact.py` mit `ImpactEvent`, `ImpactLedger`, `ImpactRunner`.
- `src/mcp_demo/shared/mock_inbox.py`, falls noch nicht vorhanden.
- `sandbox/effects/.gitkeep`.
- `var/.gitkeep` oder runtime-Erzeugung mit Doku.
- README-Abschnitt `Observable impact model`.

Akzeptanzkriterien:

- Mindestens ein Test zeigt: vulnerable direct-poisoning kann Canary wirklich in MockSink schreiben.
- Mindestens ein Test zeigt: defended direct-poisoning blockiert und schreibt stattdessen `blocked_attempt_recorded`.
- Es gibt keine echte Shell-Ausfuehrung aus User-Input.
- `DEMO_ENABLE_LOCAL_CALC_PROOF` ist default false.
- `pytest` laeuft vollstaendig.
```

Erwarteter Commit:

```text
feat: add observable impact ledger for safe exploit demos
```
