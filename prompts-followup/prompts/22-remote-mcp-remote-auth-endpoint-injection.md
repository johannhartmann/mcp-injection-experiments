# Prompt 22: `mcp-remote` OAuth metadata command-injection simulation


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

Implement a bounded simulation of untrusted OAuth metadata leading to command-injection style impact in an MCP client bridge. This must be modeled with a mock unsafe runner and a safe proof primitive only.

Experiment ID:

```text
remote-mcp-remote-auth-endpoint-injection
```

## Required MCP surfaces

```text
resources/read -> oauth_metadata
tools/call or client connect flow -> validate_metadata_and_connect
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode processes a malicious OAuth metadata fixture and creates `sandbox/effects/auth-endpoint-command-proof-<session>.txt`.
2. Defended mode rejects metadata with non-HTTPS schemes, unapproved hosts, control characters, shell metacharacter markers, or redirect abuse.
3. The mock unsafe runner cannot execute arbitrary commands.
4. Telemetry records which metadata field triggered the block.
5. UI shows the dangerous field as data, not as a runnable command.

## Implementation tasks

1. Add mock OAuth metadata fixtures:

```text
fixtures/mock_oauth/good_metadata.json
fixtures/mock_oauth/malicious_authorization_endpoint.json
```

2. Add a metadata validator with strict URL parsing.
3. Add vulnerable mode that demonstrates how trusting metadata reaches the bounded proof primitive.
4. Add defended mode that blocks before any effect.

## Observable impact

```text
sandbox/effects/auth-endpoint-command-proof-<session>.txt
```

## Acceptance criteria

- No real command execution.
- No external network calls.
- Defended mode blocks the malicious metadata fixture.
