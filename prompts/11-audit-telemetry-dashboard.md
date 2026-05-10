# Prompt 11 - Audit und Telemetry Dashboard

```text
Arbeite test-first.

Ziel: Fuehre eine einheitliche Telemetrie ein, die alle Demo-Datenfluesse, Tool-Metadaten-Aenderungen, Policy-Entscheidungen und Session-Ereignisse sichtbar macht.

Sicherheitsgrenzen:
- Logs duerfen keine echten Tokens oder Secrets enthalten.
- Canaries duerfen sichtbar sein, echte Token-Muster muessen gescrubbt werden.
- Keine persistente personenbezogene Datensammlung.

Erst Tests schreiben:
1. `tests/unit/test_telemetry_contract.py`
   - TelemetryEvent enthaelt `event_id`, `ts`, `session_id`, `experiment`, `mode`, `event_type`, `severity`, `message`, `data`.
   - Event IDs sind eindeutig.
   - Token-Muster werden gescrubbt.
2. `tests/integration/test_demo_events_api.py`
   - `/demo/events` liefert aktuelle Events.
   - Filter nach Session und Experiment funktioniert.
   - Reset loescht Demo-Events.
3. `tests/integration/test_policy_events.py`
   - Defended Tool Shadowing erzeugt Policy-Decision-Event.
   - Rug Pull erzeugt Metadata-Diff-Event.
   - Cross-Session Leak Versuch erzeugt Alert-Event.

Dann implementieren:
- `src/mcp_demo/shared/telemetry.py`
- `src/mcp_demo/web/routes.py`
- einfache HTML-Seite `/demo/events`
- JSON API `/demo/events`
- Reset Endpoint nur im local/dev mode oder mit Admin Token.

Akzeptanzkriterien:
- Jede bestehende Demo schreibt Events.
- UI zeigt Timeline pro Run.
- Logs enthalten keine echten Token-Muster.
```

Erwarteter Commit:

```text
feat: add audit telemetry dashboard
```
