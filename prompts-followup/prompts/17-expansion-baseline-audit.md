# Prompt 17: Expansion baseline audit and planning


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

Audit the current repository after the first prompt pack implementation and prepare it for the 2025-2026 exploit expansion modules.

## Test-first tasks

1. Add a test that verifies the runner can list expansion-capable experiments without failing when none are implemented yet.
2. Add a test for loading the new expansion manifest schema.
3. Add a test that an experiment can declare Agent Trap taxonomy categories in addition to OWASP categories.
4. Add a test that impact artifacts are restricted to allowed demo-owned paths.
5. Add a test that no experiment manifest can set `uses_real_third_party_apis: true`.

## Implementation tasks

1. Add the expansion manifest schema from `templates/expansion-experiment-manifest.schema.json` or adapt it to the repository's existing schema system.
2. Add Agent Trap taxonomy support:

```text
Content Injection
Semantic Manipulation
Cognitive State
Behavioural Control
Systemic
Human-in-the-Loop
```

3. Add an `expansion` section to docs and the UI catalog, but mark all expansion demos as `not_implemented` until their prompt is complete.
4. Ensure every new demo can be routed through the Streamable HTTP MCP path.
5. Add a source-note document under docs or context summarizing the research basis.

## Acceptance criteria

- The existing demo suite still passes.
- Manifest validation rejects unsafe artifact paths such as `/tmp`, `~/.ssh`, `.env`, and external URLs.
- The catalog can display placeholder entries for prompts 18-35.
- No network access is needed for tests.
