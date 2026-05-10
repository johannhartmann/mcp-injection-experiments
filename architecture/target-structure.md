# Zielarchitektur fuer die Online-Demo

## Kernidee

Die Demo soll nicht einfach einen boesartigen MCP-Server online stellen. Sie soll einen kontrollierten MCP-Client-Simulator, mehrere sichere Mock-MCP-Server und ein Telemetrie-UI kombinieren.

```text
Browser / Demo UI
  |
  | HTTPS
  v
FastAPI Demo App + MCP Client Simulator
  |
  | Streamable HTTP / JSON-RPC
  v
MCP Demo Endpoints
  +-- /mcp/direct-poisoning
  +-- /mcp/tool-shadowing
  +-- /mcp/sleeper-rug-pull
  +-- /mcp/registry-rug-pull
  +-- /mcp/cross-session-leak
  +-- /mcp/auth-confused-deputy
  +-- /mcp/ssrf-metadata
  +-- /mcp/sampling-abuse
  +-- /mcp/mock-mail
  +-- /mcp/mock-filesystem
  +-- /mcp/mock-sink
```

## Warum ein Client-Simulator?

Viele MCP-Angriffe entstehen nicht allein im Server, sondern im Zusammenspiel aus Host, Client, Tool-Planung, Tool-Auswahl, Consent, Session-Handling und Datenfluss. Ein reiner Remote-MCP-Server zeigt nur die halbe Geschichte. Der Client-Simulator erlaubt:

- vulnerable vs. defended Policies,
- reproduzierbare Tests ohne echtes LLM,
- klare Telemetrie,
- sichere Canary-Datenfluesse,
- keine Abhaengigkeit von Cursor/Claude Desktop/anderen Clients.

## Komponenten

### Transport Layer

- JSON-RPC Envelope Parser.
- Streamable HTTP POST fuer Requests.
- Optional SSE via GET fuer Events.
- Origin-Validation.
- Session-ID-Handling mit `Mcp-Session-Id`.

### Shared Safety Layer

- Canary-Generator.
- Mock-Sinks.
- Policy Engine.
- Telemetry Event Bus.
- URL Safety Validator mit Mock-Resolver.
- Fake-OAuth/JWT fuer Auth-Demos.

### Experiment Layer

Jedes Experiment implementiert denselben Vertrag:

- `list_tools(mode, session)`
- `call_tool(name, arguments, mode, session)`
- `run_scenario(mode)` fuer UI/Tests
- Manifest mit OWASP-Mapping.

### UI Layer

Minimal reicht serverseitig gerendertes HTML:

- Demo-Auswahl.
- Mode Toggle: vulnerable / defended.
- Run Button.
- Ergebnis-JSON.
- Event Timeline.
- Diff-Ansicht fuer Tool-Metadaten.
