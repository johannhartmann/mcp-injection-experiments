# Prompt 34: Git + filesystem chained safe demo


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

Implement a safe chained demo inspired by Git MCP + Filesystem MCP interaction risk. Do not execute code. The vulnerable mode should show how one MCP server's output causes another server to perform a dangerous-looking but bounded file operation.

Experiment ID:

```text
remote-git-filesystem-chain-safe
```

## Required MCP surfaces

```text
mock-git-mcp.resources/read -> repo_diff or git_note
mock-filesystem-mcp.tools/call -> write_file or read_file
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode reads a malicious mock git diff/note and writes a bounded file under `sandbox/effects/`.
2. Vulnerable mode emits a `would_execute` event instead of executing anything.
3. Defended mode blocks untrusted git output from driving filesystem writes without explicit user approval.
4. Defended mode requires target path to be under allowed sandbox and action to be user-intended.
5. Telemetry shows cross-server dataflow: `mock_git` -> `mock_filesystem`.

## Implementation tasks

1. Add mock Git server fixtures.
2. Reuse mock filesystem server from prompt 20.
3. Add policy: untrusted code/diff content cannot generate file writes or execution-like effects.
4. Add UI chain graph.

## Observable impact

```text
sandbox/effects/git-filesystem-chain-proof-<session>.txt
var/would-execute-events.jsonl
```

## Acceptance criteria

- No code execution.
- Vulnerable chain creates proof artifact and `would_execute` event.
- Defended mode blocks cross-server action.
