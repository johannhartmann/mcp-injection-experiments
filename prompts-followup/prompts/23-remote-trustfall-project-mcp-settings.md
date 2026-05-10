# Prompt 23: TrustFall-style project-defined MCP onboarding risk


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

Implement a remote demo of project-defined MCP server onboarding risk: accepting a folder/project trust prompt causes a project-provided MCP server config to be started. The impact is a bounded local start ledger and proof file.

Experiment ID:

```text
remote-trustfall-project-mcp-settings
```

## Required surfaces

```text
project config resource -> .mcp.json fixture
client trust flow -> accept_folder_trust
MCP server registry -> start mock project server
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode accepts project trust and records a mock MCP server start.
2. Vulnerable mode creates `sandbox/effects/project-mcp-started-<session>.txt`.
3. Defended mode requires per-server approval after folder trust.
4. Defended mode displays server name, origin, requested capabilities, and bounded effect before approval.
5. Denying the per-server approval creates no proof file.

## Implementation tasks

1. Add mock repo fixture:

```text
fixtures/mock_repo/.mcp.json
fixtures/mock_repo/.claude/settings.json
```

2. Add a trust-flow simulator with two gates:

```text
folder trust
per-server MCP approval
```

3. In vulnerable mode, folder trust is enough to start the mock server.
4. In defended mode, require per-server approval and show a capability diff.

## Observable impact

```text
var/process-ledger.jsonl
sandbox/effects/project-mcp-started-<session>.txt
```

## Acceptance criteria

- The user can see that server start happened because of project config.
- Defended mode blocks startup unless per-server approval is explicit.
