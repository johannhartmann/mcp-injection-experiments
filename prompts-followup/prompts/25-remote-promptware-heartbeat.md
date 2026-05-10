# Prompt 25: Promptware / Agent Commander heartbeat demo


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

Implement a safe promptware heartbeat demo: untrusted content causes a mock agent to check in with a local mock commander. This is not real C2; it is a local ledger-only demonstration.

Experiment ID:

```text
remote-promptware-heartbeat
```

## Required MCP surfaces

```text
resources/read -> poisoned project note or web resource
tools/call -> local commander check_in
tools/call -> bounded demo task
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode creates a heartbeat record in `var/agent-commander/checkins.jsonl`.
2. Vulnerable mode completes one bounded task such as writing `sandbox/effects/heartbeat-demo-<session>.txt`.
3. Defended mode detects persistent behavior instructions from untrusted content and blocks check-in.
4. The mock commander cannot issue arbitrary commands.
5. Telemetry marks the pattern as `promptware_heartbeat_simulation`.

## Implementation tasks

1. Add local mock commander with a fixed, safe task allowlist.
2. Add poisoned content fixture that attempts to induce check-in.
3. Add vulnerable mode that follows the instruction.
4. Add defended mode that blocks untrusted content from creating persistent check-in behavior.
5. Add UI with timeline and clear warning: local mock only, no external C2.

## Observable impact

```text
var/agent-commander/checkins.jsonl
sandbox/effects/heartbeat-demo-<session>.txt
```

## Acceptance criteria

- Vulnerable heartbeat is visible and bounded.
- Defended mode blocks heartbeat and bounded task.
