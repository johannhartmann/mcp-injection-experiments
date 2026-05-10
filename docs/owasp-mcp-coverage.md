# OWASP MCP Top 10 - Coverage Matrix

Diese Matrix dokumentiert, wie die geplante Online-Demo-Suite die OWASP MCP Top 10 abdeckt. Sie ist ein lebendes Dokument: jeder Implementierungsschritt aktualisiert die Spalten "Aktuelle Abdeckung" und "Teststatus".

Legende:

- **Aktuelle Abdeckung**: Was im Repo *heute* in lauffaehiger oder zumindest dokumentierter Form vorhanden ist.
- **Geplante Remote-Demo**: Welches Experiment bzw. welcher Endpoint die Kategorie spaeter abdeckt.
- **Teststatus**: `none` | `green` | `red` | `green`.
- **Mock-Surface**: Welche Demo-Komponenten den Effekt sichtbar machen, ohne echte Systeme zu beruehren.

## Coverage-Matrix MCP01..MCP10

| OWASP | Titel | Implementiert in | Mock-Surface | Teststatus |
|---|---|---|---|---|
| MCP01 | Token Mismanagement und Secret Exposure | `remote-direct-poisoning`, `remote-auth-confused-deputy` | Mock-Filesystem + Canary-Datei, Mock-Sink, FAKEJWT-Issuer | `green` |
| MCP02 | Privilege Escalation via Scope Creep | `remote-registry-rug-pull` | Fake-Registry, `permission_delta`, Pinning | `green` |
| MCP03 | Tool Poisoning | `remote-direct-poisoning`, `remote-tool-shadowing`, `remote-sleeper-rug-pull` | `lint_tool_description`, `sanitise_tool_description`, Tool-Hash-Pinning | `green` |
| MCP04 | Supply Chain Attacks | `remote-sleeper-rug-pull`, `remote-registry-rug-pull` | Description-/Schema-Hash-Diff, Fake-Registry mit Pinning | `green` |
| MCP05 | Command Injection und Execution (sim) | `remote-ssrf-metadata`, `ImpactRunner.run_local_calc_proof` (default off) | `MockResolver`, fest verdrahteter ImpactRunner ohne User-Input | `green` |
| MCP06 | Contextual Injection | `remote-direct-poisoning`, `remote-sampling-abuse` | Tool-Description-Linter, FakeLLM, `SamplingPolicy` | `green` |
| MCP07 | Insufficient AuthN/AuthZ | `remote-auth-confused-deputy` | FAKEJWT-Issuer, ConsentRegistry mit Demo-Zone-Redirect-URIs | `green` |
| MCP08 | Lack of Audit and Telemetry | `audit-telemetry-dashboard`, alle Experimente | `ImpactLedger`, `TelemetryView`, `var/telemetry.jsonl`, `/demo/events` | `green` |
| MCP09 | Shadow MCP Servers | `remote-tool-shadowing` | `CrossServerInstructionPolicy`, MockMailServer mit `.example`-Allowlist | `green` |
| MCP10 | Context Injection und Over-Sharing | `remote-cross-session-context-leak` | `PartitionedSessionStore`, `EventQueue` per `(user_id, session_id)` | `green` |

## Cross-Mapping zu Demo-Endpunkten

| Demo-Endpoint | Primaere OWASP-IDs | Sekundaer |
|---|---|---|
| `/mcp/direct-poisoning` | MCP03, MCP06 | MCP01 |
| `/mcp/tool-shadowing` | MCP03, MCP09 | MCP10 |
| `/mcp/sleeper-rug-pull` | MCP03, MCP04 | - |
| `/mcp/registry-rug-pull` | MCP02, MCP04 | - |
| `/mcp/cross-session-leak` | MCP10 | MCP08 |
| `/mcp/auth-confused-deputy` | MCP01, MCP07 | - |
| `/mcp/ssrf-metadata` | MCP05 (simuliert) | MCP01 |
| `/mcp/sampling-abuse` | MCP06, MCP08 | - |
| `/demo` (Dashboard) | MCP08 | uebergreifend |

## Pflege

Die Matrix wird nach jedem Implementierungsschritt aktualisiert. Mindestens:

- Spalte "Aktuelle Abdeckung" beim Hinzufuegen eines Experiments anpassen.
- Spalte "Teststatus" gemaess `uv run pytest`-Ergebnis setzen (`red` solange Tests rot sind, `green` sobald alle Asserts gruen sind).
- Bei Verschiebung von PoCs nach `legacy/` den Hinweis "historisch" beibehalten und auf den neuen Endpoint verlinken.
