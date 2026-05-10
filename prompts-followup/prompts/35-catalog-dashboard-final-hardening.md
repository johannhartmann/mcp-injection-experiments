# Prompt 35: Catalog dashboard, docs, and final hardening pass


# Usage pattern for this prompt

Run this prompt in Claude Code after the baseline remote MCP HTTP streaming demo pack has been implemented and all previous tests pass.

Global constraints:
- Keep all real side effects bounded to demo-owned locations only: `sandbox/effects/`, `var/mock-*`, `var/telemetry.jsonl`, `var/impact-ledger.jsonl`, `var/demo.db`, or equivalent existing paths.
- Do not read real user secrets, real `.env` files, real SSH keys, real home directories, real MCP configs, or real CI credentials.
- Do not call real Slack, GitHub, Gmail, WhatsApp, cloud metadata, or other third-party APIs.
- Do not execute arbitrary shell commands from user-controlled input. For RCE-style demos, use a bounded demo effect primitive such as `create_proof_file(effect_name, session_id)`.
- Every experiment must provide both `vulnerable` and `defended` modes.
- Every vulnerable mode must create an observable but harmless artifact.
- Every defended mode must block the same attempted effect and emit a structured block event.
- Write tests before implementation. Do not weaken tests to make them pass.

Expected existing capabilities from the first pack:
- Experiment manifests.
- Canary generator and sandbox reset.
- Impact ledger.
- Telemetry ledger.
- Mock sinks such as mock inbox, mock GitHub, mock Slack, mock CRM, mock resolver, or a way to add them.
- Streamable HTTP MCP server/client simulator.
- Vulnerable/defended policy switch.
- UI cards for user intent, observed impact, policy decision, and artifact evidence.


---


## Goal

Integrate all expansion demos into the online catalog, docs, test suite, and hardening checks.

## Test-first tasks

Write failing tests for:

1. Every implemented expansion experiment appears in `--list`.
2. Every implemented expansion experiment has vulnerable and defended modes.
3. Every implemented expansion experiment has at least one bounded vulnerable artifact and one defended block event.
4. Every implemented expansion experiment can be run through the Streamable HTTP pathway.
5. The UI catalog renders all expansion cards from manifest data.
6. The global safety test rejects network egress, real credentials, unsafe artifact paths, and shell execution from untrusted input.

## Implementation tasks

1. Add `docs/exploit-catalog-2025-2026.md` with a table:

```text
Experiment
Research family
MCP surface
Observable vulnerable impact
Defended control
OWASP mapping
Agent Trap mapping
```

2. Add `docs/agent-traps-mcp-mapping.md`.
3. Add source notes and acknowledgements.
4. Add `python -m experiments.run --all-expansion --no-network` or equivalent.
5. Add dashboard filters:

```text
MCP Surface
OWASP category
Agent Trap family
Impact type
Defended control
```

6. Add a final security hardening scan:

```text
no real URLs except docs/references
no shell=True
no subprocess with untrusted args
no external SDK credentials
no real OAuth secrets
no real Slack/GitHub tokens
no reads outside sandbox fixtures
```

## Acceptance criteria

- Full test suite passes.
- `--all --no-network` passes.
- README explains the expansion demos and the bounded real-impact model.
- Demo deployment remains safe for public online use.
