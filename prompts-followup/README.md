# MCP Exploit Expansion Follow-up Promptset

This is a follow-up promptset for Claude Code. It assumes the first MCP HTTP streaming online-demo prompt pack has already been implemented.

The goal is to extend the demo from the original MCP injection scenarios into a broader 2025-2026 exploit and agent-trap lab:

- GitHub MCP issue/PR prompt injection and public exfiltration.
- Slack MCP link-unfurling exfiltration.
- Filesystem MCP sandbox escape simulation.
- MCP Inspector / devtool auth-bypass bounded RCE proof.
- `mcp-remote` OAuth metadata command-injection simulation.
- TrustFall-style project-defined MCP server onboarding risk.
- Cross-agent privilege escalation through shared agent configs.
- Promptware / Agent Commander-style heartbeat demo.
- AI ClickFix-style UI social-engineering demo.
- Implicit tool poisoning during `tools/list`.
- Comment-and-Control style GitHub comment trigger.
- AI Agent Traps delivered through MCP resources, tool returns, prompts, sampling, and multi-agent state.
- Safe Git + filesystem chain demo.
- Catalog dashboard and final hardening pass.

## How to use

1. Finish the first prompt pack, including the observable side-effect retrofit.
2. Copy this directory into the repository root, or keep it outside and paste one prompt at a time into Claude Code.
3. Run prompts in numeric order from `prompts/17-*` onward.
4. After each prompt, run the test suite and commit the result.
5. Do not skip the defended-mode tests.

## Expected repository state before prompt 17

The first implementation should already support:

```text
python -m experiments.run --list
python -m experiments.run <experiment-id> --mode vulnerable
python -m experiments.run <experiment-id> --mode defended
python -m experiments.run --all --no-network
```

The actual commands may differ. If they differ, adapt the prompts to the implemented runner instead of changing the architecture unnecessarily.

## Safety model

This pack intentionally keeps visible effects. It does not make the demos purely fake. The side effects must be real but bounded:

```text
Allowed:
  sandbox/effects/*.txt
  var/mock-inbox.jsonl
  var/mock-github/*.jsonl
  var/mock-slack/*.jsonl
  var/mock-unfurler/*.jsonl
  var/mock-crm/*.jsonl
  var/agent-commander/*.jsonl
  var/memory-store.json
  var/impact-ledger.jsonl
  var/telemetry.jsonl

Not allowed:
  real secrets
  real home directory reads
  real shell execution from untrusted data
  real external APIs
  real cloud metadata requests
  real C2
  real exfiltration to the internet
```

## File map

```text
CLAUDE.md
PROMPT_INDEX.md
context/source-notes.md
architecture/expansion-target-structure.md
architecture/mcp-trigger-mapping.md
architecture/agent-traps-mcp-mapping.md
architecture/observable-impact-contract-v3.md
checklists/expansion-safety-checklist.md
checklists/test-first-checklist.md
templates/expansion-experiment-manifest.schema.json
templates/expansion-example-manifest.yaml
templates/impact-event-examples.jsonl
prompts/17-*.md ... prompts/35-*.md
```
