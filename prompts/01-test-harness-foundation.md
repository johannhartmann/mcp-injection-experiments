# Prompt 01 - Test Harness und Projektgrundlage

```text
Arbeite test-first.

Ziel: Lege eine minimale, testbare Python-Projektstruktur fuer die MCP Online-Demo an, ohne schon Angriffsdemos zu implementieren.

Sicherheitsgrenzen:
- Keine echten Secrets lesen.
- Keine echten Netzwerkrequests.
- Keine echten externen APIs.
- Keine Shell-Ausfuehrung aus Demo-Daten.

Erst Tests schreiben:
1. Test: `tests/unit/test_manifest_schema.py`
   - ein gueltiges Experiment-Manifest wird akzeptiert,
   - `uses_real_secrets: true` wird abgelehnt,
   - fehlende `entrypoint` wird abgelehnt.
2. Test: `tests/unit/test_experiment_registry.py`
   - Registry kann Experimente auflisten,
   - unbekanntes Experiment fuehrt zu kontrolliertem Fehler,
   - jedes Experiment hat `vulnerable` oder `defended` Mode.
3. Test: `tests/unit/test_demo_result_contract.py`
   - Demo-Ergebnis enthaelt `experiment`, `mode`, `violation_detected`, `secret_exfiltrated`, `blocked_by`, `events`.

Dann implementieren:
- `pyproject.toml` mit pytest/httpx/pydantic/FastAPI oder Starlette.
- `src/mcp_demo/shared/manifests.py`
- `src/mcp_demo/shared/results.py`
- `src/mcp_demo/experiments/registry.py`
- erstes Dummy-Manifest unter `experiments/manifests/remote-direct-poisoning.yaml`.

Akzeptanzkriterien:
- `pytest` laeuft.
- Dummy-Experiment ist registriert.
- Keine Webserver-Logik wird in diesem Schritt erzwungen.
- README erhaelt einen kurzen Abschnitt `Development` mit Testkommandos.

Stoppe nach diesem Schritt und gib eine kurze Zusammenfassung mit geaenderten Dateien und Testergebnis.
```

Erwarteter Commit:

```text
test: add experiment manifest and result contracts
```
