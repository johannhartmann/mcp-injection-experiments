# Prompt 19: Slack MCP link-unfurling exfiltration


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

Implement a safe remote demo of Slack-style link-unfurling exfiltration: an agent posts a mock Slack message containing a URL with a private canary, and a mock unfurler records the URL request.

Experiment ID:

```text
remote-slack-unfurl-leak
```

## Required MCP surfaces

```text
tools/call -> read_private_channel
tools/call -> post_message
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode posts a mock Slack message containing a URL with `CANARY_SLACK_*`.
2. Vulnerable mode causes `var/mock-unfurler/requests.jsonl` to record the same canary.
3. Defended mode blocks messages that contain private canaries in public-channel URLs.
4. Defended mode supports `unfurl_links=false` or equivalent no-preview policy.
5. The demo UI renders both the Slack message artifact and unfurler artifact.

## Implementation tasks

1. Add `mock_slack` with private and public channels.
2. Add `mock_unfurler` that records requests locally; it must not make external network calls.
3. In vulnerable mode, posting a URL to a public channel triggers the local mock unfurler.
4. In defended mode, block or strip untrusted external URLs that carry private canary data.
5. Add telemetry with data labels: `private_slack`, `public_slack`, `url_query`, `unfurler_request`.

## Observable impact

```text
var/mock-slack/messages.jsonl
var/mock-unfurler/requests.jsonl
```

## Acceptance criteria

- Vulnerable mode visibly leaks the demo canary to the mock unfurler.
- Defended mode creates a policy-block event with reason `private_canary_in_public_unfurl_url`.
- No outbound HTTP requests occur.
