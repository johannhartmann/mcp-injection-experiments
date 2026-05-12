"""Tests for the GET / landing page.

The landing page is the front door to an exploit demo, not protocol
documentation. It must hook the visitor with one concrete tool-
description-poisoning example, name the live model that drives every
run, and route them straight to the dashboard. Protocol-level details
(tools/list shapes, Streamable HTTP endpoints, Inspector hints) live
on the dashboard itself - the front door does not catalogue them.
"""

from __future__ import annotations

from httpx import AsyncClient


async def test_landing_page_returns_html(client: AsyncClient) -> None:
    response = await client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "<html" in body
    assert "MCP Injection Demos" in body


async def test_landing_page_explains_vulnerable_vs_defended(
    client: AsyncClient,
) -> None:
    body = (await client.get("/")).text
    assert "vulnerable" in body
    assert "defended" in body


async def test_landing_page_names_the_live_model(client: AsyncClient) -> None:
    """The demo is agentic; the front door names the model so visitors
    know what is actually driving each run."""

    body = (await client.get("/")).text
    assert "gemini-3.1-flash-lite" in body


async def test_landing_page_shows_a_concrete_poisoning_example(
    client: AsyncClient,
) -> None:
    """The hook is one tool-description with the hidden directive. Without
    a concrete example a visitor has no anchor for what a poisoning
    looks like."""

    body = (await client.get("/")).text
    # The example is the canonical calculator.add poisoning from
    # remote-direct-poisoning - identifiable by the IMPORTANT block and
    # the audit-gateway framing.
    assert "calculator.add" in body
    assert "IMPORTANT" in body
    assert "audit" in body.lower()
    # And concrete enough to name the sandbox file it points at.
    assert "sandbox/demo-secret.txt" in body


async def test_landing_page_has_a_dashboard_cta(client: AsyncClient) -> None:
    """Front door's primary job is to send the visitor to /demo."""

    body = (await client.get("/")).text
    assert 'href="/demo"' in body
    # Mention of the compare page anchors the "see both modes" story.
    assert "/demo/compare/" in body


async def test_landing_page_links_operational_endpoints(client: AsyncClient) -> None:
    body = (await client.get("/")).text
    for ref in ["/demo", "/demo/events", "/healthz", "/readyz"]:
        assert ref in body


async def test_landing_page_states_the_safety_boundary(client: AsyncClient) -> None:
    """The page must be honest about what is real (the model call) and
    what is mocked (everything else)."""

    body = (await client.get("/")).text
    # Real outbound is named explicitly.
    assert "generativelanguage.googleapis.com" in body
    # Mock destinations are stated.
    assert "var/" in body
    assert "sandbox/effects/" in body
    # Demo zone TLD note.
    assert ".example" in body


async def test_landing_page_does_not_require_origin(client: AsyncClient) -> None:
    """A fresh browser visitor has no Origin header for top-level navigations."""

    response = await client.get("/", headers={})
    assert response.status_code == 200
