# Prompt 30: Agent Traps: memory poisoning and delayed activation


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

Implement Cognitive State Trap demos: RAG knowledge poisoning and latent memory poisoning. The exploit should trigger later, not in the same immediate step, to show delayed activation.

Experiment ID:

```text
remote-agent-traps-memory-poisoning
```

## Required MCP surfaces

```text
resources/read -> policy_note or knowledge_doc
tools/call -> store_memory
tools/call -> later_decision or choose_tool
```

## Test-first tasks

Write failing tests for:

1. Vulnerable setup stores a poisoned memory from an untrusted resource.
2. A later run retrieves the memory and performs a bounded wrong action, such as choosing malicious helper or writing a wrong classification.
3. Defended mode stores provenance and prevents untrusted memory from controlling tool choice or policy.
4. Defended mode can still store the memory as untrusted evidence for audit.
5. UI shows Step 1 poisoning and Step 2 delayed activation.

## Implementation tasks

1. Add memory store with provenance fields:

```text
memory_id
source
trusted
created_at
usable_for_tool_choice
usable_for_policy
```

2. Add vulnerable memory store that omits provenance controls.
3. Add defended memory store that enforces trust boundaries.
4. Add delayed-run support in the experiment runner.

## Observable impact

```text
var/memory-store.json
var/later-decisions.jsonl
```

## Acceptance criteria

- Vulnerable mode requires two phases: poison then activate.
- Defended mode stores but does not act on untrusted memory.
