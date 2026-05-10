"""Origin allowlist + public-mode CORS guard tests."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mcp_demo.app import create_app
from mcp_demo.config import DemoSettings


@pytest.fixture
async def client():
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as ac:
        yield ac


async def test_disallowed_origin_is_refused_on_demo_endpoints(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/demo/scenario/remote-direct-poisoning",
        headers={"Origin": "https://evil.example"},
        json={"mode": "vulnerable", "session_id": "x"},
    )
    assert response.status_code == 403


async def test_disallowed_origin_is_refused_on_events_endpoint(
    client: AsyncClient,
) -> None:
    response = await client.get(
        "/demo/events",
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_public_mode_refuses_wildcard_origin() -> None:
    settings = DemoSettings(
        admin_token="prod-secret-please-change",
        allowed_origins=("*",),
    )
    with pytest.raises(ValueError):
        create_app(settings=settings.with_public_mode())


def test_public_mode_refuses_empty_allowlist() -> None:
    settings = DemoSettings(
        admin_token="prod-secret-please-change",
        allowed_origins=(),
    )
    with pytest.raises(ValueError):
        create_app(settings=settings.with_public_mode())


async def test_origin_check_does_not_trust_session_id_alone(
    client: AsyncClient,
) -> None:
    """Even with a known Mcp-Session-Id, a wrong Origin is refused."""

    init = await client.post(
        "/mcp/direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
    )
    sid = init.headers["Mcp-Session-Id"]

    follow_up = await client.post(
        "/mcp/direct-poisoning",
        headers={
            "Origin": "https://evil.example",
            "Mcp-Session-Id": sid,
        },
        json={"jsonrpc": "2.0", "id": "x", "method": "tools/list"},
    )
    assert follow_up.status_code == 403
