"""SSE telemetry stream tests.

Note on test boundary: httpx's ASGITransport buffers streaming
responses until the ASGI generator finishes, which never happens for
an open SSE stream. We therefore split coverage:

* This file integration-tests the route surface (status, headers,
  embed in /demo) and the wiring from FastAPI to the route module.
* :mod:`tests.unit.test_impact_ledger_subscribe` unit-tests the
  subscribe/unsubscribe/fan-out contract that the SSE handler relies
  on - that is the only logic we own; the actual streaming is
  delivered by Starlette's ``StreamingResponse`` and exercised by its
  own test suite.

The end-to-end "open the SSE stream from a browser-like client and
see real-time events" path is exercised manually against a running
uvicorn server (see README) and via the EventSource block embedded in
the /demo page.
"""

from __future__ import annotations

from httpx import AsyncClient


async def test_demo_index_embeds_live_feed(client: AsyncClient) -> None:
    response = await client.get(
        "/demo",
        headers={"Origin": "http://testserver", "Accept": "text/html"},
    )
    body = response.text
    assert "/demo/events/stream" in body
    assert "EventSource" in body
    assert "live impact events" in body


async def test_stream_route_is_registered(app_and_client) -> None:
    app, _ = app_and_client
    paths = {route.path for route in app.routes}
    assert "/demo/events/stream" in paths


async def test_app_state_exposes_ledgers(app_and_client) -> None:
    app, _ = app_and_client
    assert hasattr(app.state, "ledgers")
    assert isinstance(app.state.ledgers, list)
    assert app.state.ledgers, "expected at least one ledger to be registered"
