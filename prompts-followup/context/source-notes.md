# Source notes for expansion pack

These notes are here so Claude Code has the research context without needing to browse.

## GitHub MCP prompt injection

- Public repository content such as issues and PR comments can contain indirect prompt injection.
- A GitHub MCP-enabled agent may have access to both public untrusted content and private repositories.
- Demonstrable safe impact: private demo canary written into a mock public PR comment.
- Sources:
  - https://simonwillison.net/2025/May/26/github-mcp-exploited/
  - https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/
  - https://github.com/github/github-mcp-server/issues/844
  - https://github.blog/changelog/2025-08-13-github-mcp-server-secret-scanning-push-protection-and-more/

## Slack MCP link unfurling

- Slack-style link unfurling can convert a message containing a URL into an outbound request by a preview bot.
- A malicious prompt can cause an agent to embed sensitive data in a URL.
- Demonstrable safe impact: mock Slack message and mock unfurler request log.
- Sources:
  - https://embracethered.com/blog/posts/2025/security-advisory-anthropic-slack-mcp-server-data-leakage/
  - https://github.com/advisories/GHSA-gmx5-crwh-6vxg

## Filesystem MCP sandbox bypass

- Path validation based on string prefix checks or insufficient symlink resolution can allow escaping an intended root.
- Demonstrable safe impact: read a canary from `sandbox/outside/` through a deliberately vulnerable mock filesystem server.
- Sources:
  - https://embracethered.com/blog/posts/2025/anthropic-filesystem-mcp-server-bypass/
  - https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/

## MCP Inspector / devtool auth-bypass bounded RCE proof

- CVE-2025-49596 involved MCP Inspector versions before 0.14.1 and lack of auth between the client and proxy, allowing unauthenticated requests to launch MCP commands over stdio.
- Demonstrable safe impact: create `sandbox/effects/inspector-rce-proof.txt` through a bounded proof primitive, not arbitrary execution.
- Sources:
  - https://github.com/advisories/GHSA-7f8r-222p-6f5g
  - https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596

## mcp-remote CVE-2025-6514

- `mcp-remote` command injection was associated with crafted OAuth metadata / authorization endpoint handling when connecting to untrusted MCP servers.
- Demonstrable safe impact: validate a malicious metadata fixture and create only a bounded proof file.
- Sources:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-6514
  - https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/

## TrustFall project-defined MCP server risk

- Project-level MCP configs can cause coding agents to start MCP servers after a folder-trust decision.
- Demonstrable safe impact: mock project MCP server start recorded in `var/process-ledger.jsonl` and `sandbox/effects/project-mcp-started.txt`.
- Sources:
  - https://adversa.ai/blog/trustfall-coding-agent-security-flaw-rce-claude-cursor-gemini-cli-copilot/
  - https://github.com/adversa-ai/research/blob/main/artifacts/trustfall-mcp-settings-rce/report/article.md

## Cross-agent privilege escalation

- Agents sharing a filesystem can modify each other's rules or configuration, leading to cascading privilege changes.
- Demonstrable safe impact: Agent A changes Agent B's mock rules; Agent B makes a bounded wrong action.
- Sources:
  - https://embracethered.com/blog/posts/2025/cross-agent-privilege-escalation-agents-that-free-each-other/
  - https://simonwillison.net/2025/Sep/24/cross-agent-privilege-escalation/

## Agent Commander / promptware heartbeat

- Promptware-style payloads can make agents check in with a command dashboard and receive tasking through natural language.
- Demonstrable safe impact: local mock commander heartbeat ledger, no real C2.
- Sources:
  - https://embracethered.com/blog/posts/2026/agent-commander-your-agent-works-for-me-now/
  - https://labs.cloudsecurityalliance.org/research/csa-research-note-promptware-agent-commander-c2-20260317-csa/

## AI ClickFix

- UI or web content can trick a computer-use agent into following fake repair steps.
- Demonstrable safe impact: bounded demo action writes `sandbox/effects/clickfix-proof.txt`.
- Source:
  - https://embracethered.com/blog/posts/2025/ai-clickfix-ttp-claude/

## Comment and Control

- GitHub PR titles, issue bodies, and issue comments can be used as prompt-injection vectors against coding agents in CI/agent workflows.
- Demonstrable safe impact: fake env canary written to mock PR comment.
- Sources:
  - https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/
  - https://labs.cloudsecurityalliance.org/research/csa-research-note-comment-control-github-prompt-injection-20/

## Implicit tool poisoning

- In implicit tool poisoning, malicious instructions in a poisoned tool's metadata influence the agent to invoke a legitimate privileged tool, even if the poisoned tool is never called.
- Demonstrable safe impact: hidden BCC or mock comment created by trusted tool after only `tools/list` registered the poisoned tool.
- Source:
  - https://arxiv.org/abs/2601.07395

## MCP Sampling abuse

- Sampling lets a server request LLM completions through the client.
- Attack classes include resource theft, conversation hijacking, and covert tool invocation.
- Source:
  - https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/

## AI Agent Traps

- The Agent Traps paper defines six families: Content Injection, Semantic Manipulation, Cognitive State, Behavioural Control, Systemic, and Human-in-the-Loop traps.
- MCP can deliver traps through resources, tool returns, prompts, sampling, and session events.
- Demonstrable safe impact: hidden HTML, dynamic cloaking, memory poisoning, subagent spawning, approval fatigue, sybil consensus, and compositional fragments, all with local mock artifacts only.
- Source:
  - https://www.rivista.ai/wp-content/uploads/2026/04/ssrn-6372438.pdf
