"""HTML UI smoke tests for the demo dashboard."""

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


async def test_demo_index_lists_all_registered_experiments(
    client: AsyncClient,
) -> None:
    response = await client.get(
        "/demo",
        headers={"Origin": "http://testserver", "Accept": "text/html"},
    )
    assert response.status_code == 200
    body = response.text
    for experiment in [
        "remote-direct-poisoning",
        "remote-tool-shadowing",
        "remote-sleeper-rug-pull",
        "remote-registry-rug-pull",
        "remote-cross-session-context-leak",
        "remote-auth-confused-deputy",
        "remote-ssrf-metadata",
        "remote-sampling-abuse",
    ]:
        assert experiment in body


async def test_demo_index_contains_run_controls_per_experiment(
    client: AsyncClient,
) -> None:
    response = await client.get(
        "/demo",
        headers={"Origin": "http://testserver", "Accept": "text/html"},
    )
    body = response.text
    # Each experiment exposes a vulnerable + defended trigger.
    assert body.count('mode=vulnerable') >= 1
    assert body.count('mode=defended') >= 1
    # And points at the scenario route.
    assert "/demo/scenario/" in body


async def test_demo_index_shows_observable_impact_artifact_paths(
    client: AsyncClient,
) -> None:
    response = await client.get(
        "/demo",
        headers={"Origin": "http://testserver", "Accept": "text/html"},
    )
    body = response.text
    # Manifests carry expected artifact paths; the UI surfaces at least
    # one per experiment.
    assert "var/mock-inbox.jsonl" in body or "var/telemetry.jsonl" in body
    assert "sandbox/effects/" in body


async def test_demo_run_returns_json_and_records_event(
    client: AsyncClient,
) -> None:
    trigger = await client.post(
        "/demo/scenario/remote-direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={"mode": "vulnerable", "session_id": "ui-sess-a"},
    )
    assert trigger.status_code == 200
    body = trigger.json()
    assert body["experiment"] == "remote-direct-poisoning"
    assert body["mode"] == "vulnerable"

    timeline = await client.get(
        "/demo/events?session_id=ui-sess-a",
        headers={"Origin": "http://testserver"},
    )
    assert any(e["session_id"] == "ui-sess-a" for e in timeline.json()["events"])
