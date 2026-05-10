# API Reference

Alle Antworten sind JSON, sofern nicht anders vermerkt. Alle Routen
ausser `/healthz` pruefen `Origin` gegen `DemoSettings.allowed_origins`
und antworten mit `403` bei Mismatch. Tests-Default-Origin ist
`http://testserver`.

## Health / Readiness

### `GET /healthz`

Kein `Origin`-Check. Liefert `{"status": "ok", "name": "mcp-demo"}`.

### `GET /readyz`

`{"status": "ready", "experiments": [...], "experiment_count": n}` wo
`experiments` die Liste der validierten Manifest-IDs ist.

## MCP Streamable HTTP

Pro Experiment gibt es einen Endpunkt unter `/mcp/<entrypoint>` (siehe
Manifest). Aktuell publiziert die App `/mcp/direct-poisoning`.

### `POST /mcp/<entrypoint>`

Request:

```json
{ "jsonrpc": "2.0", "id": "...", "method": "...", "params": { ... } }
```

Pflicht-Headers:

- `Origin`: muss in `allowed_origins` stehen.
- `Mcp-Session-Id`: nach `initialize` Pflicht; wird abgewiesen bei
  fehlend (`-32001`) oder unbekannt (`-32002`).

Unterstuetzte Methoden:

- `initialize` - liefert `{ protocolVersion, capabilities, serverInfo }`
  und setzt im Response-Header `Mcp-Session-Id`. Optional
  `params.demo.mode = "vulnerable" | "defended"`, um den Mode dieser
  Session festzulegen (nur fuer das direct-poisoning Experiment
  relevant; weitere Experimente nutzen den Demo-Endpunkt
  `/demo/scenario/...`).
- `tools/list` - liefert `{"tools": [...]}` mit pro Tool `name`,
  `description`, `inputSchema`.
- `tools/call` - `params: {"name": "...", "arguments": {...}}`. Liefert
  `{"content": [...], "isError": bool}`.

Batch-Requests werden mit `-32600 INVALID_REQUEST` und expliziter
Begruendung abgelehnt.

JSON-RPC-Fehler kommen als `200 OK` mit `error: {code, message}` (per
JSON-RPC 2.0 Standard). HTTP-Level-Fehler:

- `400` JSON-Body ungueltig oder Session-Header fehlt/unbekannt.
- `403` `Origin` nicht in der Allowlist.
- `405` `GET /mcp/<entrypoint>` (SSE noch nicht implementiert).

### Beispiel

```bash
curl -i -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":"init-1","method":"initialize",
    "params":{"protocolVersion":"2025-03-26","capabilities":{},
              "clientInfo":{"name":"demo-client","version":"0.1.0"}}}'
```

## Demo-Dashboard

### `GET /demo` *(HTML)*

Serverseitig gerendertes HTML mit einer Karte pro Experiment (Titel,
OWASP-Tags, Vulnerable/Defended-Run-Buttons, Observable-Impact-Pfade
aus dem Manifest). Kein externes CDN.

### `POST /demo/scenario/<experiment_id>`

Body:

```json
{ "mode": "vulnerable" | "defended", "session_id": "..." }
```

Antwort: `200 OK` mit `DemoResult` JSON:

```json
{
  "experiment": "remote-direct-poisoning",
  "mode": "defended",
  "violation_detected": true,
  "secret_exfiltrated": false,
  "blocked_by": ["canary_exfiltration_policy"],
  "events": [
    {
      "type": "policy_decision",
      "policy": "canary_exfiltration_policy",
      "allowed": false,
      "reason": "..."
    }
  ]
}
```

Fehler: `404` bei unbekanntem Experiment, `400` bei ungueltigem JSON,
`403` bei falschem `Origin`.

### `GET /demo/events`

Query-Parameter:

- `session_id=<id>` - filtert auf eine Session.
- `experiment=<id>` - filtert auf ein Experiment.

`Accept: application/json` (Default) liefert `{"events": [...]}` mit
`TelemetryEvent`-Objekten:

```json
{
  "event_id": "evt_...",
  "ts": "2026-05-10T12:00:00Z",
  "session_id": "sess-a",
  "experiment": "remote-tool-shadowing",
  "mode": "vulnerable",
  "event_type": "mock_message_sent",
  "severity": "info",
  "message": "malicious.helper: hidden BCC added: ['attacker@attacker.example']",
  "data": { ... }
}
```

`Accept: text/html` rendert eine kompakte Tabelle (kein CDN, kein JS).

### `POST /demo/reset`

Pflicht-Header: `X-Demo-Admin-Token: <token>`. Default-Token ist
`local-dev`, ueberschreibbar via `DEMO_ADMIN_TOKEN`. Body:

```json
{ "session_id": "..." }
```

Loescht alle In-Memory-Events einer Session. JSONL-Audit-Trails
(`var/telemetry.jsonl`, `var/mock-inbox.jsonl`) bleiben unangetastet.

Fehler: `401` bei fehlendem/falschem Token, `400` bei fehlender
`session_id`, `403` bei falschem `Origin`.

## DemoResult-Felder

| Feld | Typ | Bedeutung |
|---|---|---|
| `experiment` | str | Manifest-ID. |
| `mode` | `"vulnerable"` \| `"defended"` | Aktueller Modus. |
| `violation_detected` | bool | Hat das Experiment eine Verletzung beobachtet? |
| `secret_exfiltrated` | bool | Wurde ein Canary in `MockSink` registriert? |
| `blocked_by` | `list[str]` | Rule-IDs, die im defended Mode geblockt haben. |
| `events` | `list[dict]` | Strukturierte Events fuer UI/Tests. |

`mode == "defended"` mit `violation_detected=True`, `secret_exfiltrated=True`
und leerem `blocked_by` ist kohaerent inkonsistent und wird durch den
Pydantic-Validator abgelehnt.

## Manifest-Schema

Pflichtfelder pro Experiment-Manifest:

```yaml
id: kebab-case-id
title: ...
owasp: [MCP03, MCP09]
mode_support: [vulnerable, defended]
requires_network: false
uses_real_secrets: false  # const False; jeder andere Wert -> abgelehnt
safe_mode: true           # const True
entrypoint: /mcp/...
expected_vulnerable_result: ...
expected_defended_result: ...
```

Optional: `mitigations: [...]`, `references: [...]`, `impact: {vulnerable: {type, artifact, user_visible}, defended: {...}}`.

`uses_real_secrets: true` und `safe_mode: false` werden vom Validator
mit `ManifestValidationError` abgelehnt - die Registry weigert sich,
solche Manifeste zu laden.
