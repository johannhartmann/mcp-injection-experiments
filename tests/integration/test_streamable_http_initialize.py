"""Integration tests for the Streamable HTTP MCP initialize handshake."""

from __future__ import annotations

import re

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


async def test_initialize_returns_jsonrpc_response(client: AsyncClient) -> None:
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={
            "Origin": "http://testserver",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "demo-client", "version": "0.1.0"},
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == "init-1"
    assert "result" in body
    assert body["result"]["protocolVersion"] == "2025-03-26"
    assert body["result"]["serverInfo"]["name"]


async def test_initialize_emits_session_id_header(client: AsyncClient) -> None:
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={
            "Origin": "http://testserver",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
    )
    assert response.status_code == 200

    session_id = response.headers.get("Mcp-Session-Id")
    assert session_id is not None
    # Visible printable ASCII, no control chars.
    assert re.fullmatch(r"[A-Za-z0-9_-]{16,}", session_id)


async def test_session_ids_are_unique(client: AsyncClient) -> None:
    seen: set[str] = set()
    for i in range(5):
        response = await client.post(
            "/mcp/direct-poisoning",
            headers={"Origin": "http://testserver"},
            json={
                "jsonrpc": "2.0",
                "id": i,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        sid = response.headers["Mcp-Session-Id"]
        assert sid not in seen
        seen.add(sid)


async def test_subsequent_request_without_session_id_is_refused(
    client: AsyncClient,
) -> None:
    init = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
    )
    assert init.status_code == 200

    # Skip Mcp-Session-Id intentionally.
    follow_up = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={"jsonrpc": "2.0", "id": "tools-1", "method": "tools/list"},
    )
    assert follow_up.status_code == 400
    body = follow_up.json()
    assert body["error"]["code"] < 0


async def test_unknown_session_id_is_refused(client: AsyncClient) -> None:
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={
            "Origin": "http://testserver",
            "Mcp-Session-Id": "definitely-not-a-real-session-id",
        },
        json={"jsonrpc": "2.0", "id": "tools-1", "method": "tools/list"},
    )
    assert response.status_code == 400
