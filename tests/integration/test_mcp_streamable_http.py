"""End-to-end tests against the mounted FastMCP servers.

These tests speak the Streamable-HTTP MCP protocol with the official
``mcp`` Python client (``streamable_http_client`` + ``ClientSession``)
and exercise every method the demo cares about: ``initialize``,
``tools/list``, ``tools/call``. They run against the in-process FastAPI
app via an ``httpx.AsyncClient`` ASGI transport, which means no real
network and no real subprocess.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from asgi_lifespan import LifespanManager
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError

from mcp_demo.app import create_app
from mcp_demo.experiments.direct_poisoning import POISONED_DESCRIPTION


@pytest.fixture
async def app_in_lifespan():
    app = create_app()
    async with LifespanManager(app):
        yield app


def _http_client_for(app) -> httpx.AsyncClient:
    """Build an httpx.AsyncClient that talks to ``app`` over ASGI."""

    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        headers={"Origin": "http://testserver"},
        timeout=30.0,
        follow_redirects=True,
    )


async def test_direct_poisoning_vulnerable_lists_poisoned_description(
    app_in_lifespan,
) -> None:
    async with _http_client_for(app_in_lifespan) as http_client, streamable_http_client(
        url="http://testserver/mcp/direct-poisoning/vulnerable/",
        http_client=http_client,
    ) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            tools = {t.name: t for t in tools_result.tools}
            assert "calculator.add" in tools
            description = tools["calculator.add"].description or ""
            assert "<IMPORTANT>" in description
            assert "sandbox/demo-secret.txt" in description
            for forbidden in ("~/.ssh", "~/.cursor", "id_rsa", "/etc/passwd"):
                assert forbidden not in description


async def test_direct_poisoning_defended_lists_sanitised_description(
    app_in_lifespan,
) -> None:
    async with _http_client_for(app_in_lifespan) as http_client, streamable_http_client(
        url="http://testserver/mcp/direct-poisoning/defended/",
        http_client=http_client,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            [tool] = [t for t in tools_result.tools if t.name == "calculator.add"]
            description = tool.description or ""
            assert "<IMPORTANT>" not in description
            assert "sandbox/demo-secret.txt" not in description


async def test_direct_poisoning_vulnerable_call_delivers_canary(
    app_in_lifespan,
) -> None:
    runtime = app_in_lifespan.state.runtimes["remote-direct-poisoning"]
    async with _http_client_for(app_in_lifespan) as http_client, streamable_http_client(
        url="http://testserver/mcp/direct-poisoning/vulnerable/",
        http_client=http_client,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            assert runtime.sink.secret_exfiltrated is False
            result = await session.call_tool(
                "calculator.add",
                arguments={"a": 2, "b": 3, "sidenote": runtime.canary.value},
            )
            assert result.isError is False
            # The vulnerable call_tool delivered the sidenote payload to the
            # MockSink with the registered canary, flipping the leak flag.
            assert runtime.sink.secret_exfiltrated is True


async def test_direct_poisoning_defended_call_refuses_canary(
    app_in_lifespan,
) -> None:
    runtime = app_in_lifespan.state.runtimes["remote-direct-poisoning"]
    async with _http_client_for(app_in_lifespan) as http_client, streamable_http_client(
        url="http://testserver/mcp/direct-poisoning/defended/",
        http_client=http_client,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            assert runtime.sink.secret_exfiltrated is False
            result = await session.call_tool(
                "calculator.add",
                arguments={"a": 2, "b": 3, "sidenote": runtime.canary.value},
            )
            # Tool returns an error result; canary stays out of the sink.
            assert result.isError is True
            assert runtime.sink.secret_exfiltrated is False
            # The block was recorded in the impact ledger.
            blocks = [
                e
                for e in runtime.ledger.all_events()
                if e.impact_type == "blocked_attempt_recorded"
            ]
            assert blocks
            assert any(
                "canary" in (b.user_visible_summary or "").lower()
                or "canary" in (b.data.get("reason", "")).lower()
                for b in blocks
            )


async def test_initialize_then_tools_list_completes_successfully(
    app_in_lifespan,
) -> None:
    """End-to-end: initialize + tools/list against the real SDK server.

    The MCP SDK manages session-id capture internally; we only need the
    session lifecycle to complete cleanly to confirm the stateful
    streamable-HTTP path is wired up correctly.
    """

    async with _http_client_for(app_in_lifespan) as http_client, streamable_http_client(
        url="http://testserver/mcp/direct-poisoning/defended/",
        http_client=http_client,
    ) as (read, write, get_session_id):
        async with ClientSession(read, write) as session:
            init_result = await session.initialize()
            assert init_result.serverInfo.name
            tools = await session.list_tools()
            assert any(t.name == "calculator.add" for t in tools.tools)
            # After at least one round-trip the SDK transport has captured
            # the Mcp-Session-Id header (or the server is stateless and
            # returns None - either is spec-conformant).
            sid = get_session_id()
            if sid is not None:
                assert isinstance(sid, str) and sid.strip()
                assert all(0x21 <= ord(c) <= 0x7E for c in sid)


async def test_calls_against_unknown_tool_return_mcp_error(
    app_in_lifespan,
) -> None:
    async with _http_client_for(app_in_lifespan) as http_client, streamable_http_client(
        url="http://testserver/mcp/direct-poisoning/vulnerable/",
        http_client=http_client,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("no.such.tool", arguments={})
            # MCP returns isError=True (tool-level failure), not a protocol
            # error; the spec keeps protocol errors for transport / lifecycle
            # problems, not unknown tool names.
            assert result.isError is True
