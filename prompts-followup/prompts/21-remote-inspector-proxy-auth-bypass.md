# Prompt 21: MCP Inspector / devtool auth-bypass bounded RCE proof


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

Implement a bounded remote demo of a devtool proxy auth-bypass class inspired by MCP Inspector RCE reports. The demo must never launch arbitrary commands. It should prove impact by creating a bounded proof file only.

Experiment ID:

```text
remote-inspector-proxy-auth-bypass
```

## Required MCP surfaces

```text
HTTP proxy route -> launch_server simulation
MCP stdio launch -> bounded proof primitive only
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode accepts an unauthenticated launch request and creates `sandbox/effects/inspector-rce-proof-<session>.txt`.
2. Defended mode rejects unauthenticated launch requests.
3. Defended mode requires a CSRF/nonce or explicit demo auth token for admin launch.
4. User-controlled strings cannot become commands or arguments.
5. Telemetry marks the effect as `bounded_rce_proof`, not real execution.

## Implementation tasks

1. Add a mock inspector proxy route.
2. Add a safe `create_proof_file()` effect primitive.
3. Add a vulnerable mode that lacks auth and calls the proof primitive.
4. Add a defended mode that requires auth and origin checks.
5. Add UI card explaining why `calc.exe`-style proof is represented by a sandbox proof file in a remote demo.

## Observable impact

```text
sandbox/effects/inspector-rce-proof-<session>.txt
```

## Acceptance criteria

- No arbitrary subprocess execution exists.
- The vulnerable proof file is real and visible.
- The defended mode blocks without creating the proof file.
