# Expansion source notes (2025-2026)

These notes record the public research the expansion-pack experiments are
modelled on. Each entry summarises the attack class and points at the
sandbox effect we use to show it without touching real systems.

## GitHub MCP prompt injection (`remote-github-issue-leak`, `remote-comment-and-control`)

Public repository content (issue bodies, PR titles, comments) reaches
agents that also have access to private repositories. The demo plants a
private canary in a mock private repo, lets the public-issue content
instruct the agent to copy it into a mock public PR comment, and shows
the same flow blocked when private-to-public dataflow is tainted.

References:
- https://simonwillison.net/2025/May/26/github-mcp-exploited/
- https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/
- https://github.com/github/github-mcp-server/issues/844
- https://github.blog/changelog/2025-08-13-github-mcp-server-secret-scanning-push-protection-and-more/
- https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-comment-control-github-prompt-injection-20/

## Slack MCP link unfurling (`remote-slack-unfurl-leak`)

A poisoned message can convince an agent to embed sensitive data in a
URL it then posts to a public channel. Slack-style link unfurling turns
that URL into an outbound preview request that leaks the data through
the unfurler. Demo replaces both Slack and the unfurler with local mocks.

References:
- https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/
- https://github.com/advisories/GHSA-gmx5-crwh-6vxg

## Filesystem MCP sandbox bypass (`remote-filesystem-sandbox-escape`)

Path validation by string prefix or insufficient symlink resolution can
escape an intended sandbox root. Demo uses a deliberately vulnerable
mock validator and a defended one that resolves canonical paths and
checks `relative_to` against an allowlisted root.

References:
- https://embracethered.com/blog/posts/2025/anthropic-filesystem-mcp-server-bypass/
- https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/

## MCP Inspector / devtool auth-bypass (`remote-inspector-proxy-auth-bypass`)

CVE-2025-49596 covered MCP Inspector versions before 0.14.1 where the
client-to-proxy hop lacked auth, letting an unauthenticated request
launch MCP commands. Demo creates a bounded proof file via
`ImpactRunner` instead of running anything; defended mode requires a
demo admin token + Origin check.

References:
- https://github.com/advisories/GHSA-7f8r-222p-6f5g
- https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596

## `mcp-remote` OAuth metadata command-injection (`remote-mcp-remote-auth-endpoint-injection`)

CVE-2025-6514 covered `mcp-remote` accepting crafted OAuth metadata that
a downstream runner treated as a command. Demo uses a deliberately
unsafe runner that creates a proof file when a bad metadata fixture
arrives, and a defended runner that validates the metadata first.

References:
- https://nvd.nist.gov/vuln/detail/CVE-2025-6514
- https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/

## TrustFall-style project MCP onboarding (`remote-trustfall-project-mcp-settings`)

Coding agents that auto-start MCP servers based on a project's
`.mcp.json` after a folder-trust prompt collapse two distinct trust
decisions into one. Demo separates folder trust from per-server consent
and shows how the defended path needs explicit approval per server.

References:
- https://adversa.ai/blog/trustfall-coding-agent-security-flaw-rce-claude-cursor-gemini-cli-copilot/
- https://github.com/adversa-ai/research/blob/main/artifacts/trustfall-mcp-settings-rce/report/article.md

## Cross-agent privilege escalation (`remote-cross-agent-config-priv-esc`)

Agents that share a filesystem can rewrite each other's rules and trip a
peer into running on attacker-influenced settings. Demo has Agent A
write Agent B's mock rules; Agent B's later action carries the new
rule. Defended mode allows only owner-signed config writes.

References:
- https://embracethered.com/blog/posts/2025/cross-agent-privilege-escalation-agents-that-free-each-other/
- https://simonwillison.net/2025/Sep/24/cross-agent-privilege-escalation/

## Promptware / Agent Commander (`remote-promptware-heartbeat`)

Promptware-style payloads plant persistent instructions that turn the
agent into a long-running C2 client. Demo records check-ins to a local
mock commander ledger only - never to the open internet.

References:
- https://embracethered.com/blog/posts/2026/agent-commander-your-agent-works-for-me-now/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-promptware-agent-commander-c2-20260317-csa/

## AI ClickFix (`remote-ai-clickfix`)

A computer-use agent reads a fake support page that instructs it to
"repair" the system by running a command. Demo uses a mock browser
resource and a mock terminal tool whose only allowlisted action is the
ImpactRunner proof primitive.

References:
- https://embracethered.com/blog/posts/2025/ai-clickfix-ttp-claude/

## Implicit tool poisoning (`remote-implicit-tool-poisoning`)

A poisoned tool's metadata never gets called, but its description still
reaches the planner via `tools/list`, where it influences the call to a
trusted privileged tool. Demo registers the poisoned tool, never calls
it, and observes the trusted mock-mail tool gaining a hidden BCC.

References:
- https://arxiv.org/abs/2601.07395

## MCP sampling abuse (covered by `remote-sampling-abuse` baseline)

Resource theft, conversation hijack and covert tool invocation through
the sampling channel.

References:
- https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/

## AI Agent Traps (`remote-agent-traps-*`)

Six families: Content Injection, Semantic Manipulation, Cognitive State,
Behavioural Control, Systemic, Human-in-the-Loop. Mapping table in
[`docs/agent-traps-mcp-mapping.md`](agent-traps-mcp-mapping.md).

References:
- https://www.rivista.ai/wp-content/uploads/2026/04/ssrn-6372438.pdf
