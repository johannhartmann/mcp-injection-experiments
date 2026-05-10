"""Origin allowlist + public-mode CORS guard tests."""

from __future__ import annotations

from httpx import AsyncClient
from mcp_demo.app import create_app

import pytest

from mcp_demo.config import DemoSettings




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


async def test_top_level_navigation_without_origin_reaches_dashboard(
    client: AsyncClient,
) -> None:
    """Browsers do not send Origin on top-level GET navigation. The
    read-only HTML routes must therefore allow missing Origin and only
    reject explicit cross-origin requests."""

    # /demo: no Origin header at all - the realistic browser case.
    response = await client.get("/demo")
    assert response.status_code == 200
    assert "MCP Demo Experiments" in response.text

    # /demo/events: same rationale.
    response = await client.get("/demo/events", headers={"Accept": "text/html"})
    assert response.status_code == 200


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


async def test_mcp_endpoint_refuses_disallowed_origin(
    client: AsyncClient,
) -> None:
    """The official MCP servers mounted under /mcp/<id>/<mode> enforce
    transport-security origin checks via FastMCP's TransportSecuritySettings.
    A request with a fremder Origin is refused with HTTP 4xx before the
    JSON-RPC layer sees it."""

    response = await client.post(
        "/mcp/direct-poisoning/vulnerable/",
        headers={
            "Origin": "https://evil.example",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "demo-client", "version": "0.0.1"},
            },
        },
    )
    assert response.status_code in {400, 403, 421}
