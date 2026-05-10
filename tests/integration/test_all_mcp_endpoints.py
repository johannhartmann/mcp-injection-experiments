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
]


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
