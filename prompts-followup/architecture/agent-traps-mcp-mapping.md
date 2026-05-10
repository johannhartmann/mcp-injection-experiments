# AI Agent Traps mapped to MCP

The Agent Traps taxonomy can be represented as MCP-triggerable demos.

| Trap family | MCP delivery channel | Demo module |
|---|---|---|
| Content Injection | `resources/read` returns HTML, Markdown, metadata, hidden comments | `remote-agent-traps-hidden-html` |
| Semantic Manipulation | `resources/read` returns biased or framed content that corrupts reasoning | Add fixtures inside hidden HTML / sybil demos |
| Cognitive State | `resources/read` + memory tool stores poisoned but plausible memory | `remote-agent-traps-memory-poisoning` |
| Behavioural Control | `resources/read` or tool return contains explicit hidden action instruction | `remote-ai-clickfix`, `remote-github-issue-leak` |
| Systemic | Multiple MCP servers/resources produce correlated false evidence | `remote-agent-traps-sybil-and-fragments` |
| Human-in-the-Loop | Approval queue and UI cards manipulate the human overseer | `remote-agent-traps-approval-fatigue` |

Required UI view for trap demos:

```text
Human-visible view:
  What a normal browser/preview would show.

Agent-parsed view:
  The raw content passed to the agent.

Delta:
  Hidden or machine-only content.

Impact:
  Artifact actually created in vulnerable mode.

Defense:
  Normalization, provenance, taint, consent, or policy rule that blocked it.
```
