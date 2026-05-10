# Prompt 31: Agent Traps: subagent spawning


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

Implement a Behavioural Control Trap where untrusted content asks an orchestrator to spawn a subagent. In vulnerable mode, the subagent performs a bounded mock action. In defended mode, untrusted resources cannot spawn subagents.

Experiment ID:

```text
remote-agent-traps-subagent-spawning
```

## Required MCP surfaces

```text
resources/read -> contributing_md or task_doc
tools/call -> spawn_subagent
tools/call -> subagent_perform_review
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode spawns a subagent due to untrusted resource content.
2. Vulnerable subagent writes an approval or action record.
3. Defended mode blocks subagent creation from untrusted content.
4. Defended mode allows subagent creation only from trusted operator intent.
5. Telemetry links subagent identity to source provenance.

## Implementation tasks

1. Add mock orchestrator MCP tool `spawn_subagent`.
2. Add mock subagent action ledger.
3. Add policy rule: untrusted resources cannot request new agents or privilege-bearing delegation.
4. Add UI graph showing Parent Agent -> Subagent -> Mock Action.

## Observable impact

```text
var/subagents.jsonl
var/mock-code-review/approvals.jsonl
```

## Acceptance criteria

- Vulnerable mode creates a real subagent ledger entry.
- Defended mode blocks before subagent creation.
