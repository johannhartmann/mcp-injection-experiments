# OWASP MCP Top 10 - Coverage Matrix

Diese Matrix dokumentiert, wie die geplante Online-Demo-Suite die OWASP MCP Top 10 abdeckt. Sie ist ein lebendes Dokument: jeder Implementierungsschritt aktualisiert die Spalten "Aktuelle Abdeckung" und "Teststatus".

Legende:

- **Aktuelle Abdeckung**: Was im Repo *heute* in lauffaehiger oder zumindest dokumentierter Form vorhanden ist.
- **Geplante Remote-Demo**: Welches Experiment bzw. welcher Endpoint die Kategorie spaeter abdeckt.
- **Teststatus**: `none` | `planned` | `red` | `green`.
- **Mock-Surface**: Welche Demo-Komponenten den Effekt sichtbar machen, ohne echte Systeme zu beruehren.

## Coverage-Matrix MCP01..MCP10

| OWASP | Titel | Aktuelle Abdeckung | Geplante Remote-Demo | Mock-Surface | Teststatus |
|---|---|---|---|---|---|
| MCP01 | Token Mismanagement und Secret Exposure | Historisch in `direct-poisoning.py` (poisoned tool description liest `~/.cursor/mcp.json`, `~/.ssh/id_rsa.pub`). Nicht testbar, unsicher. | `remote-direct-poisoning` (Canary statt echter Datei), `remote-auth-confused-deputy` (Fake-OAuth-Audience). | Mock-Filesystem mit Canary-Datei, Mock-Sink, Fake-OAuth-Issuer. | `planned` |
| MCP02 | Privilege Escalation via Scope Creep | Nicht abgedeckt. | `remote-registry-rug-pull` (Permission-Delta zwischen Pin und Update, Re-Approval-Pflicht im defended Mode). | Fake-Registry mit zwei Versionen, Permission-Diff-Engine, Mock-Sink. | `planned` |
| MCP03 | Tool Poisoning | Historisch in `direct-poisoning.py` und `shadowing.py` (poisoned descriptions, hidden instructions). Nur als STDIO-Snippet. | `remote-direct-poisoning`, `remote-tool-shadowing` (Cross-Server-Instruction-Linter im defended Mode). | Tool-Description-Linter, Cross-Server-Policy, Mock-Mail, Mock-Sink. | `planned` |
| MCP04 | Supply Chain Attacks | Historisch angedeutet in `whatsapp-takeover.py` (Sleeper Rug Pull via `~/.mcp-triggered`). | `remote-sleeper-rug-pull` (Tool-Description-/Schema-Hash-Diff), `remote-registry-rug-pull` (Pinning, Hash-Diff, Version-Lock). | Fake-Registry, Description-Hash-Diff, Telemetry-Event bei Drift. | `planned` |
| MCP05 | Command Injection und Execution | Negativ vorhanden: Snippets nutzen `os.system("touch ~/.mcp-triggered")`. Wird in der neuen Demo nicht reproduziert. | Nur als Konfig-/Allowlist-Simulation; Effekt wird auf `sandbox/effects/rce-proof-<session>.txt` reduziert (`ImpactRunner`). Kein User-Input in Subprozess. | `ImpactRunner` mit fester Allowlist, Mock-Filesystem. | `planned` |
| MCP06 | Contextual Injection | Historisch in den poisoned descriptions. | `remote-direct-poisoning` (Tainting), `remote-sampling-abuse` (Context Boundaries und Budget). | Tainting-Tags an Tool-Outputs, Fake-LLM, Budgetzaehler. | `planned` |
| MCP07 | Insufficient AuthN/AuthZ | Nicht abgedeckt. | `remote-auth-confused-deputy` (Audience-Validation, per-Client-Consent, Redirect-URI-Check). | Fake-OAuth-Issuer, Fake-Resource-Server, Audience-Checker. | `planned` |
| MCP08 | Lack of Audit and Telemetry | Nicht abgedeckt. | `audit-telemetry-dashboard` (Event Timeline, JSONL-Ledger, UI-Visualisierung), zusaetzlich Telemetry-Events in jedem Experiment. | `var/telemetry.jsonl`, Impact Ledger, Web-Dashboard. | `planned` |
| MCP09 | Shadow MCP Servers | Historisch in `shadowing.py` (poisoned add-Tool manipuliert Verhalten eines fremden `send_email`). | `remote-tool-shadowing` (Trusted-Server-Registry, Server-Identity-Pruefung, Cross-Server-Instruction-Block). | Trusted-Server-Allowlist, Mock-Mail mit Identity-Tag, Telemetry. | `planned` |
| MCP10 | Context Injection und Over-Sharing | Nicht abgedeckt. | `remote-cross-session-context-leak` (zwei Demo-Sessions, Canary aus Session A leakt in Session B im vulnerable Mode). | Zwei isolierte Sessions, Event Queue partitioniert nach `user_id:session_id`. | `planned` |

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
