# Expansion target structure

The first pack should already have a structure for experiments, shared utilities, docs, and tests. Add the expansion without replacing that structure.

Recommended additions:

```text
experiments/
  remote_github_issue_leak/
  remote_slack_unfurl_leak/
  remote_filesystem_sandbox_escape/
  remote_inspector_proxy_auth_bypass/
  remote_mcp_remote_auth_endpoint_injection/
  remote_trustfall_project_mcp_settings/
  remote_cross_agent_config_priv_esc/
  remote_promptware_heartbeat/
  remote_ai_clickfix/
  remote_implicit_tool_poisoning/
  remote_comment_and_control/
  remote_agent_traps_hidden_html/
  remote_agent_traps_memory_poisoning/
  remote_agent_traps_subagent_spawning/
  remote_agent_traps_approval_fatigue/
  remote_agent_traps_sybil_and_fragments/
  remote_git_filesystem_chain_safe/
shared/
  mock_github.py
  mock_slack.py
  mock_unfurler.py
  mock_filesystem.py
  mock_oauth_metadata.py
  mock_agents.py
  mock_commander.py
  trap_fixtures.py
  provenance.py
  policy_engine.py
  telemetry.py
  impact.py
ui/
  cards/
    ExploitExpansionCard.*
    HumanVsAgentView.*
    TrapTaxonomyBadge.*
docs/
  exploit-catalog-2025-2026.md
  agent-traps-mcp-mapping.md
  expansion-safety-model.md
```

Keep naming consistent with the implemented stack. If the project uses hyphenated directories, keep that style. If it uses Python packages, keep snake_case package names and manifest IDs with hyphens.
