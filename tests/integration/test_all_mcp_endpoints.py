"""Catalog test: every experiment with ``build_mcp_servers`` answers
``initialize`` and ``tools/list`` through the official MCP client.

The list grows commit-by-commit as new experiments gain real FastMCP
servers. Once an experiment lands here, its catalog row in
``docs/exploit-catalog-2025-2026.md`` may flip its MCP-surface column
from ``via /demo/scenario`` to ``via /mcp/<id>/<mode>/``.
"""

from __future__ import annotations

import pytest

from tests.integration._mcp_client_helper import mcp_session


# Each entry: (experiment_id, mount_slug). The slug is the path
# component used in app.py's _mount_mcp helper.
_MOUNTED = [
    ("remote-direct-poisoning", "direct-poisoning"),
    ("remote-tool-shadowing", "tool-shadowing"),
    ("remote-sleeper-rug-pull", "sleeper-rug-pull"),
    ("remote-implicit-tool-poisoning", "implicit-tool-poisoning"),
    ("remote-cross-session-context-leak", "cross-session-context-leak"),
    ("remote-cross-agent-config-priv-esc", "cross-agent-config-priv-esc"),
    ("remote-sampling-abuse", "sampling-abuse"),
    ("remote-auth-confused-deputy", "auth-confused-deputy"),
    ("remote-inspector-proxy-auth-bypass", "inspector-proxy-auth-bypass"),
    ("remote-mcp-remote-auth-endpoint-injection", "mcp-remote-auth-endpoint-injection"),
    ("remote-ssrf-metadata", "ssrf-metadata"),
    ("remote-filesystem-sandbox-escape", "filesystem-sandbox-escape"),
    ("remote-git-filesystem-chain-safe", "git-filesystem-chain-safe"),
    ("remote-github-issue-leak", "github-issue-leak"),
    ("remote-slack-unfurl-leak", "slack-unfurl-leak"),
    ("remote-comment-and-control", "comment-and-control"),
    ("remote-trustfall-project-mcp-settings", "trustfall-project-mcp-settings"),
    ("remote-registry-rug-pull", "registry-rug-pull"),
    ("remote-promptware-heartbeat", "promptware-heartbeat"),
    ("remote-ai-clickfix", "ai-clickfix"),
    ("remote-agent-traps-hidden-html", "agent-traps-hidden-html"),
    ("remote-agent-traps-memory-poisoning", "agent-traps-memory-poisoning"),
    ("remote-agent-traps-subagent-spawning", "agent-traps-subagent-spawning"),
    ("remote-agent-traps-approval-fatigue", "agent-traps-approval-fatigue"),
    ("remote-agent-traps-sybil-and-fragments", "agent-traps-sybil-and-fragments"),
]


def test_every_registered_experiment_is_in_the_mounted_list() -> None:
    """All 25 experiments now have a real MCP server. Catch regressions
    if a future commit adds an experiment manifest without the
    corresponding build_mcp_servers."""

    from mcp_demo.app import create_app

    app = create_app()
    expected = {f"/mcp/{slug}/{mode}" for _, slug in _MOUNTED for mode in ("vulnerable", "defended")}
    mounted_paths = {
        getattr(r, "path", "")
        for r in app.router.routes
    }
    missing = expected - mounted_paths
    assert not missing, f"missing mount paths: {sorted(missing)}"


@pytest.fixture
async def app(client):  # noqa: ARG001 - reuse the conftest lifespan
    yield client._transport.app  # type: ignore[attr-defined]


@pytest.mark.parametrize("experiment_id, slug", _MOUNTED)
@pytest.mark.parametrize("mode", ["vulnerable", "defended"])
async def test_initialize_and_tools_list(
    app, experiment_id: str, slug: str, mode: str
) -> None:
    """initialize + tools/list succeed and the response includes at
    least one tool whose name does not start with an underscore."""

    async with mcp_session(app, f"/mcp/{slug}/{mode}/") as session:
        tools = await session.list_tools()
        assert tools.tools, f"{experiment_id}/{mode} returned no tools"
        for tool in tools.tools:
            assert tool.name and not tool.name.startswith("_")
