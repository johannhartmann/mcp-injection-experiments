# OWASP MCP Top 10 Mapping fuer Remote-Demo

| OWASP | Remote-Demo-Modul | Online geeignet | Defended Fokus |
|---|---|---:|---|
| MCP01 Token Mismanagement & Secret Exposure | `remote-auth-confused-deputy`, `remote-direct-poisoning` | Ja | fake token audience, canary leak block |
| MCP02 Privilege Escalation via Scope Creep | `remote-registry-rug-pull` | Ja | permission delta, re-approval |
| MCP03 Tool Poisoning | `remote-direct-poisoning`, `remote-tool-shadowing` | Ja | tool description linter, cross-server policy |
| MCP04 Supply Chain Attacks | `remote-registry-rug-pull`, `remote-sleeper-rug-pull` | Ja | pinning, hash diff, version lock |
| MCP05 Command Injection & Execution | spaeter nur als config simulation | Nur simuliert | no subprocess, allowlist parser |
| MCP06 Contextual Injection | `remote-direct-poisoning`, `sampling-abuse` | Ja | tainting, context boundaries |
| MCP07 Insufficient AuthN/AuthZ | `remote-auth-confused-deputy` | Ja | audience validation, per-client consent |
| MCP08 Lack of Audit and Telemetry | `audit-telemetry-dashboard` | Ja | structured event timeline |
| MCP09 Shadow MCP Servers | `remote-tool-shadowing` | Ja | trusted server registry, server identity |
| MCP10 Context Injection & Over-Sharing | `remote-cross-session-context-leak` | Ja | user/session isolation |
