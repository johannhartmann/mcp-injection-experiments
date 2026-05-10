"""Header-level checks for the Streamable HTTP MCP transport.

The transport must validate ``Origin`` against an allowlist (no wildcard in
public mode) and behave predictably when ``Accept`` is absent or wrong. SSE
is exposed via GET; for endpoints that do not need SSE the GET path returns
``405 Method Not Allowed``.
"""

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


async def test_disallowed_origin_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "https://attacker.example.com"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
    )
    assert response.status_code == 403


async def test_allowed_origin_is_accepted(client: AsyncClient) -> None:
    response = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
    )
    assert response.status_code == 200


async def test_request_without_origin_is_rejected(client: AsyncClient) -> None:
    """No Origin header in browser context = no allowlisting possible."""

    response = await client.post(
        "/mcp/direct-poisoning",
        headers={},  # explicit: no Origin
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
    )
    assert response.status_code == 403


async def test_get_returns_405_when_sse_not_implemented(client: AsyncClient) -> None:
    response = await client.get(
        "/mcp/direct-poisoning",
        headers={
            "Origin": "http://testserver",
            "Accept": "text/event-stream",
        },
    )
    assert response.status_code == 405


async def test_healthz_does_not_require_origin(client: AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
