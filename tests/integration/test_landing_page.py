"""Tests for the GET / landing page."""

from __future__ import annotations

from httpx import AsyncClient


async def test_landing_page_returns_html(client: AsyncClient) -> None:
    response = await client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "<html" in body
    assert "MCP" in body


async def test_landing_page_explains_vulnerable_vs_defended(
    client: AsyncClient,
) -> None:
    response = await client.get("/")
    body = response.text
    assert "vulnerable" in body
    assert "defended" in body


async def test_landing_page_lists_two_http_surfaces(client: AsyncClient) -> None:
    body = (await client.get("/")).text
    assert "/mcp/&lt;experiment&gt;/&lt;mode&gt;/" in body or "/mcp/<experiment>/<mode>/" in body
    assert "/demo/scenario/" in body


async def test_landing_page_lists_every_experiment(client: AsyncClient) -> None:
    body = (await client.get("/")).text
    for experiment_id in [
        "remote-direct-poisoning",
        "remote-tool-shadowing",
        "remote-github-issue-leak",
        "remote-agent-traps-hidden-html",
        "remote-git-filesystem-chain-safe",
    ]:
        assert experiment_id in body


async def test_landing_page_links_operational_endpoints(client: AsyncClient) -> None:
    body = (await client.get("/")).text
    for ref in ["/demo", "/demo/events", "/healthz", "/readyz"]:
        assert ref in body


async def test_landing_page_includes_safety_warning(client: AsyncClient) -> None:
    body = (await client.get("/")).text
    assert "Safety model" in body
    assert ".example" in body
    assert "FAKEJWT" in body


async def test_landing_page_does_not_require_origin(client: AsyncClient) -> None:
    """A fresh browser visitor has no Origin header for top-level navigations."""

    response = await client.get("/", headers={})
    assert response.status_code == 200
