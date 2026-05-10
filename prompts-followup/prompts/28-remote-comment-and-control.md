# Prompt 28: Comment-and-Control style GitHub comment trigger


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

Implement a safe demo of GitHub comment/PR-title prompt injection against a coding-agent workflow. The vulnerable mode writes a fake env canary to a mock PR comment.

Experiment ID:

```text
remote-comment-and-control
```

## Required MCP surfaces

```text
resources/read -> pr_title, issue_body, pr_comment
tools/call -> read_fake_ci_env
tools/call -> post_pr_comment
```

## Test-first tasks

Write failing tests for:

1. Vulnerable mode reads a malicious PR title or comment fixture and posts `CANARY_FAKE_CI_*` into a mock PR comment.
2. Defended mode treats GitHub comments/titles as untrusted and prevents fake env data from reaching public comments.
3. Defended mode redacts canaries from public outputs.
4. Telemetry includes `source=github_pr_comment`, `sink=public_pr_comment`, and `secret_type=fake_ci_env`.
5. UI renders a CI-agent style timeline.

## Implementation tasks

1. Reuse or extend mock GitHub from prompt 18.
2. Add fake CI env fixture with demo canary only.
3. Add coding-agent workflow simulator:

```text
read PR metadata
run review
post review comment
```

4. Add defended controls:

```text
untrusted GitHub text taint
secret/canary detector
public sink guard
```

## Observable impact

```text
var/mock-github/pr-comments.jsonl
```

## Acceptance criteria

- Vulnerable mode demonstrates the full comment-to-comment loop.
- Defended mode blocks and redacts.
