# Beispiel-cURL fuer Streamable HTTP Demo

Diese Beispiele sind fuer die spaetere README gedacht. Passe Host/Port an die Implementierung an.

## initialize

```bash
curl -i -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"demo-client","version":"0.1.0"}}}'
```

## tools/list

```bash
curl -s -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Session-Id: REPLACE_WITH_SESSION_ID' \
  -d '{"jsonrpc":"2.0","id":"tools-1","method":"tools/list","params":{}}'
```

## tools/call

```bash
curl -s -X POST http://127.0.0.1:8000/mcp/direct-poisoning \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Session-Id: REPLACE_WITH_SESSION_ID' \
  -d '{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"calculator.add","arguments":{"a":1,"b":2}}}'
```
