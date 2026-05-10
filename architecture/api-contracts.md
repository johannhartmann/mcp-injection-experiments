# API- und Test-Vertraege

## Demo Run API

```http
POST /demo/run/{experiment_id}
Content-Type: application/json

{
  "mode": "vulnerable",
  "scenario": "default"
}
```

Response:

```json
{
  "experiment": "remote-direct-poisoning",
  "mode": "vulnerable",
  "violation_detected": true,
  "secret_exfiltrated": true,
  "blocked_by": [],
  "events": [
    {
      "type": "dataflow",
      "source": "mock_filesystem.canary",
      "destination": "mock_sink",
      "allowed": true
    }
  ]
}
```

## MCP Endpoint Mindestumfang

Ein Demo-MCP-Endpunkt muss mindestens folgende JSON-RPC-Methoden unterstuetzen:

```text
initialize
tools/list
tools/call
```

Beispiel `tools/call`:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "tools/call",
  "params": {
    "name": "calculator.add",
    "arguments": {"a": 1, "b": 2}
  }
}
```

## Session Contract

- Wenn `initialize` eine `Mcp-Session-Id` setzt, muessen Folge-Requests diese ID mitsenden.
- Session-IDs muessen zufaellig, nicht vorhersagbar und sichtbar ASCII sein.
- Session-IDs duerfen nicht als Authentisierung verwendet werden.
- Event Queues muessen mindestens nach `user_id:session_id` partitioniert werden.

## Telemetry Event Contract

```json
{
  "event_id": "evt_...",
  "ts": "2026-05-10T12:00:00Z",
  "session_id": "...",
  "experiment": "remote-tool-shadowing",
  "mode": "defended",
  "event_type": "policy_decision",
  "severity": "warning",
  "message": "cross-server recipient rewrite blocked",
  "data": {
    "policy": "cross_server_instruction_policy",
    "allowed": false
  }
}
```

## Manifest Contract

Siehe `templates/experiment-manifest.schema.json`.
