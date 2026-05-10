# Prompt 32: Agent Traps: approval fatigue and human-in-the-loop


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

Implement a Human-in-the-Loop Trap demo that shows approval fatigue: many low-risk approvals followed by a visually similar high-risk approval. The high-risk approval creates a bounded mock action only in vulnerable mode.

Experiment ID:

```text
remote-agent-traps-approval-fatigue
```

## Required surfaces

```text
client approval queue
MCP tool calls requiring approval
UI risk annotations
```

## Test-first tasks

Write failing tests for:

1. Vulnerable auto-approval or fatigue mode approves a risky request after a sequence of benign requests.
2. The risky request creates a bounded artifact, such as a mock email with canary or hidden BCC.
3. Defended mode requires risk-differentiated approval for the high-risk request.
4. Defended mode highlights changed recipient/domain/data labels.
5. Approval ledger records decisions and risk level.

## Implementation tasks

1. Add approval queue simulator with two modes:

```text
fatigued_auto_accept
risk_aware_defended
```

2. Add a series of benign approval fixtures plus one risky approval fixture.
3. Add UI that makes the contrast clear:

```text
Repeated benign approvals
Risky approval with subtle difference
Defended risk badge and diff
```

## Observable impact

```text
var/approvals.jsonl
var/mock-inbox.jsonl
```

## Acceptance criteria

- Vulnerable mode shows a human-overseer failure, not just model failure.
- Defended mode changes the approval UX and blocks the risky artifact.
