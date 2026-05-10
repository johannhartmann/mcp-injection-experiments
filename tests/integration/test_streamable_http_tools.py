"""Tests for tools/list and tools/call on the demo MCP endpoint."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mcp_demo.app import create_app


@pytest.fixture
async def client():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as ac:
        yield ac


async def _initialize(client: AsyncClient) -> str:
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
    )
    assert response.status_code == 200
    return response.headers["Mcp-Session-Id"]


async def test_tools_list_returns_at_least_one_tool(client: AsyncClient) -> None:
    session_id = await _initialize(client)
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver", "Mcp-Session-Id": session_id},
        json={"jsonrpc": "2.0", "id": "tools-1", "method": "tools/list"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == "tools-1"
    tools = body["result"]["tools"]
    assert len(tools) >= 1
    names = [t["name"] for t in tools]
    assert "calculator.add" in names
    [add] = [t for t in tools if t["name"] == "calculator.add"]
    assert add["description"]
    assert "inputSchema" in add


async def test_tools_call_invokes_demo_tool(client: AsyncClient) -> None:
    session_id = await _initialize(client)
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver", "Mcp-Session-Id": session_id},
        json={
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "calculator.add",
                "arguments": {"a": 2, "b": 3},
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "call-1"
    content = body["result"]["content"]
    assert content[0]["type"] == "text"
    assert "5" in content[0]["text"]


async def test_tools_call_unknown_tool_returns_jsonrpc_error(
    client: AsyncClient,
) -> None:
    session_id = await _initialize(client)
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver", "Mcp-Session-Id": session_id},
        json={
            "jsonrpc": "2.0",
            "id": "call-x",
            "method": "tools/call",
            "params": {"name": "no-such-tool", "arguments": {}},
        },
    )
    assert response.status_code == 200  # JSON-RPC errors are 200 with error body
    body = response.json()
    assert "error" in body
    assert body["error"]["code"] < 0


async def test_unknown_method_returns_method_not_found(client: AsyncClient) -> None:
    session_id = await _initialize(client)
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver", "Mcp-Session-Id": session_id},
        json={"jsonrpc": "2.0", "id": "x", "method": "telepathy/start"},
    )
    body = response.json()
    assert "error" in body
    # JSON-RPC METHOD_NOT_FOUND
    assert body["error"]["code"] == -32601
