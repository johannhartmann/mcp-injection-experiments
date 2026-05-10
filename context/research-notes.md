# Research Notes fuer Claude Code

Diese Notizen geben Kontext fuer die Umsetzung. Pruefe beim Implementieren trotzdem den aktuellen Codezustand im Repo.

## Ausgangsrepo

`johannhartmann/mcp-injection-experiments` ist ein Fork von `invariantlabs-ai/mcp-injection-experiments` und enthaelt aktuell im Wesentlichen:

- `direct-poisoning.py`
- `shadowing.py`
- `whatsapp-takeover.py`
- `README.md`

Die README beschreibt:

- Direct Poisoning: Tool-Beschreibung verleitet Agenten zum Leaken sensibler Dateien.
- Tool Shadowing: manipuliert Verhalten eines `send_email`-Tools eines anderen Servers.
- WhatsApp takeover: Shadowing plus Sleeper Rug Pull, bei dem Tool-Interface erst beim zweiten Laden boesartig wird.

## Streamable HTTP Anforderungen

MCP Streamable HTTP nutzt einen einzelnen Endpoint, der `POST` und optional `GET` unterstuetzt. `POST` traegt JSON-RPC-Messages. Ein Server kann `application/json` oder `text/event-stream` antworten. `GET` kann eine SSE-Verbindung fuer Servernachrichten oeffnen. Stateful Server koennen bei `initialize` eine `Mcp-Session-Id` ausgeben, die Clients anschliessend mitsenden muessen.

Sicherheitsrelevante Punkte:

- Origin Header validieren.
- Lokal nicht ohne Grund an `0.0.0.0` binden.
- Authentisierung fuer Verbindungen vorsehen.
- Session-IDs muessen zufaellig und nicht vorhersagbar sein.
- Session-ID ist keine Authentisierung.

## Security Best Practices fuer Remote-Demos

Wichtige Demo-Klassen:

- Confused Deputy: per-client consent und Redirect-URI-Validation testen.
- Token Passthrough: Tokens muessen fuer den MCP-Server ausgestellt sein; Audience pruefen.
- SSRF: OAuth-/Metadata-URLs nur ueber Validator/Mock-Resolver; private und link-local Bereiche blockieren.
- Session Hijacking/Event Injection: Event Queues nach `user_id:session_id` partitionieren.

## Geeignete Online-Demos

Sehr geeignet:

- Remote Direct Poisoning mit Canary statt echten Dateien.
- Remote Tool Shadowing mit Mock-Mail.
- Remote Sleeper Rug Pull mit Tool-Description-/Schema-Hash-Diff.
- Remote Registry Rug Pull mit Fake-Registry.
- Cross-Session Context Leak mit zwei Demo-Sessions.
- Auth Confused Deputy mit Fake OAuth.
- SSRF Metadata Discovery als Mock-Resolver-Simulation.
- Audit/Telemetry-Dashboard.
- Sampling Abuse mit Fake-LLM und Budgetzaehler.

Nicht als echte Online-Aktion geeignet:

- echte lokale Datei-Exfiltration,
- echte STDIO-RCE,
- echte WhatsApp-/Mail-/GitHub-Aktionen,
- echte SSRF gegen interne Netze oder Cloud-Metadata.
