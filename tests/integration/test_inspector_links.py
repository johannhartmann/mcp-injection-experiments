"""MCP Inspector deep-link tests.

The /demo cards and the /demo/compare/<id> page must each surface a
copy-pasteable upstream MCP URL pointing at the running demo, so users
can attach a local ``@modelcontextprotocol/inspector`` instance to the
exact mount path. We do not embed Inspector itself - it is a separate
Node app and not co-hostable.
"""

from __future__ import annotations

from httpx import AsyncClient


async def test_demo_index_lists_per_mode_inspector_urls(
    client: AsyncClient,
) -> None:
    response = await client.get(
        "/demo",
        headers={"Origin": "http://testserver", "Accept": "text/html"},
    )
    body = response.text
    # The disclosure summary anchor must be present on at least one card.
    assert "Open in MCP Inspector" in body
    # Per-card URLs include both the vulnerable and defended slugs and
    # are anchored at the request's own origin (testserver here).
    assert "http://testserver/mcp/direct-poisoning/vulnerable/" in body
    assert "http://testserver/mcp/direct-poisoning/defended/" in body
    # The launch instruction is shown verbatim.
    assert "npx @modelcontextprotocol/inspector" in body


async def test_compare_page_shows_inspector_disclosure(
    client: AsyncClient,
) -> None:
    response = await client.get(
        "/demo/compare/remote-direct-poisoning",
        headers={"Origin": "http://testserver"},
    )
    body = response.text
    assert "Open in MCP Inspector" in body
    assert "http://testserver/mcp/direct-poisoning/vulnerable/" in body
    assert "http://testserver/mcp/direct-poisoning/defended/" in body
    assert "npx @modelcontextprotocol/inspector" in body


async def test_inspector_urls_use_request_origin(client: AsyncClient) -> None:
    """If the user is browsing on a non-default origin, the URLs should
    reflect that origin verbatim."""
    response = await client.get(
        "/demo",
        headers={"Origin": "http://localhost:8000", "Accept": "text/html"},
    )
    body = response.text
    assert "http://localhost:8000/mcp/direct-poisoning/vulnerable/" in body


async def test_copy_button_handler_present(client: AsyncClient) -> None:
    body = (
        await client.get(
            "/demo",
            headers={"Origin": "http://testserver", "Accept": "text/html"},
        )
    ).text
    # The clipboard handler is the only place data-copy-target is read.
    assert "data-copy-target" in body
    assert "navigator.clipboard" in body
