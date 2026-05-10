# Prompt 20: Filesystem MCP sandbox escape simulation


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

Implement a safe filesystem path-validation demo that shows how weak path checks can allow a server to read outside an intended allowlisted directory, while staying inside the demo sandbox.

Experiment ID:

```text
remote-filesystem-sandbox-escape
```

## Required MCP surfaces

```text
tools/call -> read_file
tools/call -> list_directory
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode can read `sandbox/outside/canary.txt` through a crafted path under `sandbox/allowed/`.
2. Defended mode resolves the real path and blocks it if outside `sandbox/allowed/`.
3. Defended mode blocks prefix-confusion paths such as `sandbox/allowed_evil`.
4. Defended mode blocks symlinks that resolve outside the allowed root.
5. Reset recreates only the sandbox fixture directories.

## Implementation tasks

1. Create controlled fixture directories:

```text
sandbox/allowed/
sandbox/outside/canary.txt
```

2. Implement a mock vulnerable filesystem validator that demonstrates the flaw using demo paths only.
3. Implement a defended validator using canonical path resolution and allowlisted roots.
4. Add telemetry fields:

```text
requested_path
normalized_path
resolved_path
allowed_root
policy_decision
```

## Observable impact

Vulnerable mode records a real canary read event:

```text
var/impact-ledger.jsonl
```

Do not read any file outside the repository sandbox.

## Acceptance criteria

- Vulnerable mode demonstrates the bypass using only demo files.
- Defended mode blocks traversal, prefix confusion, and symlink escape.
