# Prompt 24: Cross-agent privilege escalation via shared configs


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

Implement a demo where one compromised mock agent modifies another agent's configuration through shared filesystem or MCP tools, causing the second agent to perform a bounded wrong action.

Experiment ID:

```text
remote-cross-agent-config-priv-esc
```

## Required MCP surfaces

```text
tools/call -> write_agent_config
resources/read -> agent_rules
tools/call -> perform_agent_action
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode allows Agent A to write Agent B's rules.
2. Agent B later reads the modified rules and performs a bounded wrong action.
3. Defended mode blocks cross-agent config writes.
4. Defended mode allows only owner-signed or admin-approved config changes.
5. Telemetry records agent identity, config owner, writer identity, and policy decision.

## Implementation tasks

1. Add mock agents A and B with separate config paths.
2. Add a vulnerable shared-config tool.
3. Add a defended policy that denies cross-agent writes by default.
4. Add UI timeline:

```text
Step 1: untrusted instruction reaches Agent A
Step 2: Agent A modifies Agent B config
Step 3: Agent B acts under modified config
Step 4: defended mode blocks at Step 2
```

## Observable impact

```text
var/agents/agent-b-rules.json
var/agents/agent-b-actions.jsonl
```

## Acceptance criteria

- Vulnerable mode shows real config mutation and later action.
- Defended mode preserves Agent B config unchanged.
