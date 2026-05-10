# Prompt 26: AI ClickFix-style UI social-engineering demo


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

Implement a demo where a webpage or UI resource convinces a computer-use style mock agent to perform a fake repair action. The action must be a bounded proof file only.

Experiment ID:

```text
remote-ai-clickfix
```

## Required MCP surfaces

```text
resources/read -> support_page.html
tools/call -> run_bounded_demo_action
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode reads a support-page fixture and runs the bounded demo action.
2. Vulnerable mode creates `sandbox/effects/clickfix-proof-<session>.txt`.
3. Defended mode treats webpage repair instructions as untrusted and requires explicit trusted operator approval.
4. Defended mode blocks terminal-like actions requested by webpage content.
5. UI shows human-visible page versus agent-parsed instruction.

## Implementation tasks

1. Add a mock browser MCP resource for `support_page.html`.
2. Add a mock terminal MCP tool with exactly one safe action: create proof file.
3. Add a policy rule: untrusted web content cannot request terminal/system actions.
4. Add UI card for the social-engineering chain.

## Observable impact

```text
sandbox/effects/clickfix-proof-<session>.txt
var/ui-actions.jsonl
```

## Acceptance criteria

- No real terminal commands.
- Vulnerable proof file is created.
- Defended mode blocks and logs `untrusted_webpage_requested_system_action`.
