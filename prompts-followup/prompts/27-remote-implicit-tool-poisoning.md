# Prompt 27: Implicit tool poisoning via tools/list


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

Implement an implicit tool poisoning demo where a poisoned tool is never invoked, but its metadata influences the planner to call a legitimate privileged tool with altered arguments.

Experiment ID:

```text
remote-implicit-tool-poisoning
```

## Required MCP surfaces

```text
tools/list -> poisoned low-privilege tool metadata
tools/call -> trusted_mail.send_email or mock equivalent
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode calls `tools/list`, never calls the poisoned tool, yet the trusted mail tool receives a hidden BCC or altered recipient.
2. Defended mode rejects cross-tool instructions in tool metadata.
3. Defended mode displays tool metadata hash and lint findings.
4. Telemetry shows `poisoned_tool_invoked: false` and `trusted_tool_impacted: true` in vulnerable mode.
5. UI explains why registration-time metadata is the trigger.

## Implementation tasks

1. Add poisoned metadata fixture for a harmless-looking tool, such as `markdown_formatter`.
2. Add a trusted mock mail tool.
3. Add vulnerable planner behavior that uses all tool metadata as context.
4. Add defended metadata linter:

```text
reject references to other tools
reject recipient rewrites
reject hidden instructions
reject data exfiltration language
require user-visible description diff
```

## Observable impact

```text
var/mock-inbox.jsonl
var/tool-planning-trace.jsonl
```

## Acceptance criteria

- The poisoned tool is not called.
- The vulnerable impact still occurs through the trusted tool.
- Defended mode blocks during `tools/list` or planning.
