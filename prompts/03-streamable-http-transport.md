# Prompt 03 - Streamable HTTP Transport Foundation

```text
Arbeite test-first.

Ziel: Implementiere einen minimalen MCP Streamable HTTP Transport fuer die Demo. Nutze das offizielle MCP Python SDK, falls es im aktuellen Projekt sinnvoll verfuegbar ist. Wenn nicht, implementiere eine kleine Demo-Fassade fuer JSON-RPC und dokumentiere die Entscheidung.

Sicherheitsgrenzen:
- Kein echter Remote-Zugriff ausser lokalem Testserver.
- Keine beliebigen User-URLs.
- Origin-Validation muss aktiv sein.
- Session-ID ist keine Authentisierung.

Erst Tests schreiben:
1. `tests/unit/test_jsonrpc.py`
   - gueltige JSON-RPC Request wird geparst.
   - fehlendes `jsonrpc: 2.0` wird abgelehnt.
   - Batch Requests werden entweder unterstuetzt oder sauber mit dokumentiertem Fehler abgelehnt.
2. `tests/integration/test_streamable_http_initialize.py`
   - `POST /mcp/direct-poisoning` mit `initialize` liefert JSON-RPC Response.
   - Response enthaelt `Mcp-Session-Id`, falls Server stateful ist.
   - Session-ID ist nicht vorhersagbar und sichtbares ASCII.
3. `tests/integration/test_streamable_http_headers.py`
   - fehlender oder falscher `Accept` Header wird kontrolliert abgelehnt oder kompatibel behandelt, aber dokumentiert.
   - unerlaubter `Origin` wird abgelehnt.
   - erlaubter `Origin` wird akzeptiert.
4. `tests/integration/test_streamable_http_tools.py`
   - `tools/list` gibt mindestens ein Demo-Tool zurueck.
   - `tools/call` ruft ein Demo-Tool auf.
5. Optional, falls SSE implementiert wird: `tests/integration/test_streamable_http_sse.py`
   - `GET` mit `Accept: text/event-stream` oeffnet SSE oder liefert 405, falls fuer diesen Endpoint nicht benoetigt.

Dann implementieren:
- `src/mcp_demo/app.py`
- `src/mcp_demo/transport/jsonrpc.py`
- `src/mcp_demo/transport/streamable_http.py`
- `src/mcp_demo/transport/sse.py` falls noetig
- `src/mcp_demo/config.py` mit Origin-Allowlist und Demo-Mode Defaults
- `GET /healthz`

Akzeptanzkriterien:
- HTTP-Integrationstests laufen mit `httpx`/ASGI-Testclient.
- Es gibt mindestens einen funktionierenden MCP-Demo-Endpoint.
- Origin-Validation ist getestet.
- README enthaelt Beispiel-cURL fuer `initialize`, `tools/list`, `tools/call`.
```

Erwarteter Commit:

```text
feat: add MCP streamable HTTP demo transport
```
