# Agent Traps mapped to MCP surfaces

The Agent Traps taxonomy (Content Injection, Semantic Manipulation,
Cognitive State, Behavioural Control, Systemic, Human-in-the-Loop) maps
naturally onto MCP-triggerable demos because every trap class needs a
delivery channel and MCP gives us six well-defined ones.

| Trap family | MCP delivery channel | Demo module |
|---|---|---|
| Content Injection | `resources/read` returns HTML, Markdown, metadata or hidden comments | `remote-agent-traps-hidden-html` |
| Semantic Manipulation | `resources/read` returns biased/framed content that corrupts reasoning | shared fixtures inside hidden-html and sybil demos |
| Cognitive State | `resources/read` plus a memory tool stores poisoned-but-plausible memory | `remote-agent-traps-memory-poisoning` |
| Behavioural Control | `resources/read` or tool return contains explicit hidden action instruction | `remote-ai-clickfix`, `remote-github-issue-leak`, `remote-comment-and-control`, `remote-implicit-tool-poisoning`, `remote-agent-traps-subagent-spawning` |
| Systemic | Multiple MCP servers/resources produce correlated false evidence | `remote-agent-traps-sybil-and-fragments`, `remote-cross-agent-config-priv-esc` |
| Human-in-the-Loop | Approval queue and UI cards manipulate the human overseer | `remote-agent-traps-approval-fatigue`, `remote-trustfall-project-mcp-settings` |

## UI presentation

Every trap demo card presents five panels:

1. **Human-visible view** - what a normal browser/preview would show.
2. **Agent-parsed view** - the raw content actually passed to the agent.
3. **Delta** - the hidden or machine-only content (the part that drives
   the trap).
4. **Impact** - the artefact created in vulnerable mode.
5. **Defense** - the normalisation, provenance, taint, consent, or
   policy rule that blocked the same flow in defended mode.

## Defense building blocks

The defended modes reuse a small, named set of mitigations:

- **Provenance labels** mark every piece of data with its source and
  trust level (`untrusted_public`, `untrusted_web`, `private_canary`,
  ...).
- **Taint propagation** ensures that data labelled private cannot reach
  a sink labelled public.
- **Recipient/domain allowlists** keep mock-mail, mock-slack, mock-github
  and mock-chat targets inside the `.example` zone.
- **Tool-metadata linting** scans `tools/list` payloads for `<IMPORTANT>`
  blocks, silencing phrases, credential paths and cross-tool rewrites.
- **Session isolation** keys state by `(user_id, session_id)`, never by
  session id alone.
- **Resolved-path validation** runs `Path.resolve` and `relative_to`
  against an allowlisted root.
- **Audience and scope checks** verify FAKEJWT tokens against the
  expected MCP-server audience and a scope subset.
- **Per-server consent and re-consent** rebind approvals when a server's
  fingerprint or scope drifts.
- **Per-server sampling budgets** cap LLM-style requests per session.
- **Approval-queue risk highlighting** makes risky requests visually
  distinct in the human-in-the-loop UX.
- **Human-vs-agent view delta** surfaces the cloaked portion of any
  resource so the operator sees exactly what the agent would.
