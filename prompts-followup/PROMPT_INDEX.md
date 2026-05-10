# Prompt index

Run these prompts after the first remote MCP demo pack is complete.

| Prompt | Goal |
|---|---|
| 17 | Expansion baseline audit and gap check |
| 18 | GitHub MCP issue/PR prompt-injection leak |
| 19 | Slack MCP link-unfurling exfiltration |
| 20 | Filesystem MCP sandbox escape simulation |
| 21 | MCP Inspector / devtool auth-bypass bounded RCE proof |
| 22 | `mcp-remote` OAuth metadata command-injection simulation |
| 23 | TrustFall-style project-defined MCP onboarding risk |
| 24 | Cross-agent privilege escalation via shared configs |
| 25 | Promptware / Agent Commander heartbeat demo |
| 26 | AI ClickFix-style UI social-engineering demo |
| 27 | Implicit tool poisoning via `tools/list` |
| 28 | Comment-and-Control style GitHub comment trigger |
| 29 | Agent Traps: hidden HTML and dynamic cloaking |
| 30 | Agent Traps: memory poisoning and delayed activation |
| 31 | Agent Traps: subagent spawning |
| 32 | Agent Traps: approval fatigue and human-in-the-loop |
| 33 | Agent Traps: sybil consensus and compositional fragments |
| 34 | Git + filesystem chained safe demo |
| 35 | Catalog dashboard, final docs, and hardening pass |

Recommended workflow:

```text
paste prompt 17
run tests
commit
paste prompt 18
run tests
commit
...
```
