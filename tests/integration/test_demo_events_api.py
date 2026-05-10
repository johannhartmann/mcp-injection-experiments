"""HTTP-level tests for the audit / telemetry dashboard."""

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


async def test_events_endpoint_returns_recent_telemetry(
    client: AsyncClient,
) -> None:
    # Trigger one experiment run via the scenario API exposed by the
    # debug endpoint that the dashboard uses.
    trigger = await client.post(
        "/demo/scenario/remote-direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={"mode": "vulnerable", "session_id": "sess-a"},
    )
    assert trigger.status_code == 200

    response = await client.get(
        "/demo/events",
        headers={"Origin": "http://testserver", "Accept": "application/json"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "events" in body
    events = body["events"]
    assert any(e["session_id"] == "sess-a" for e in events)


async def test_events_endpoint_filters_by_session(client: AsyncClient) -> None:
    for sid in ["sess-a", "sess-b"]:
        await client.post(
            "/demo/scenario/remote-direct-poisoning",
            headers={"Origin": "http://testserver"},
            json={"mode": "vulnerable", "session_id": sid},
        )

    response = await client.get(
        "/demo/events?session_id=sess-a",
        headers={"Origin": "http://testserver"},
    )
    body = response.json()
    assert all(e["session_id"] == "sess-a" for e in body["events"])
    assert any(e["session_id"] == "sess-a" for e in body["events"])


async def test_events_endpoint_filters_by_experiment(
    client: AsyncClient,
) -> None:
    await client.post(
        "/demo/scenario/remote-direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={"mode": "vulnerable", "session_id": "sess-c"},
    )
    response = await client.get(
        "/demo/events?experiment=remote-direct-poisoning",
        headers={"Origin": "http://testserver"},
    )
    body = response.json()
    assert all(
        e["experiment"] == "remote-direct-poisoning" for e in body["events"]
    )


async def test_reset_endpoint_clears_session_events(
    client: AsyncClient,
) -> None:
    await client.post(
        "/demo/scenario/remote-direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={"mode": "vulnerable", "session_id": "sess-d"},
    )
    reset = await client.post(
        "/demo/reset",
        headers={
            "Origin": "http://testserver",
            "X-Demo-Admin-Token": "local-dev",
        },
        json={"session_id": "sess-d"},
    )
    assert reset.status_code == 200

    response = await client.get(
        "/demo/events?session_id=sess-d",
        headers={"Origin": "http://testserver"},
    )
    body = response.json()
    assert body["events"] == []


async def test_reset_endpoint_requires_admin_token(client: AsyncClient) -> None:
    response = await client.post(
        "/demo/reset",
        headers={"Origin": "http://testserver"},
        json={"session_id": "sess-x"},
    )
    assert response.status_code == 401


async def test_events_html_view_renders(client: AsyncClient) -> None:
    response = await client.get(
        "/demo/events",
        headers={"Origin": "http://testserver", "Accept": "text/html"},
    )
    assert response.status_code == 200
    assert "<html" in response.text.lower() or "<table" in response.text.lower()
