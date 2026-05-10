"""End-to-end checks that defended demos emit the expected policy events."""

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


async def _run(client: AsyncClient, experiment: str, mode: str, session_id: str) -> None:
    response = await client.post(
        f"/demo/scenario/{experiment}",
        headers={"Origin": "http://testserver"},
        json={"mode": mode, "session_id": session_id},
    )
    assert response.status_code == 200, response.text


async def test_defended_tool_shadowing_emits_policy_event(
    client: AsyncClient,
) -> None:
    await _run(client, "remote-tool-shadowing", "defended", "p-tool-shadow")

    response = await client.get(
        "/demo/events?session_id=p-tool-shadow",
        headers={"Origin": "http://testserver"},
    )
    events = response.json()["events"]
    assert any(
        e["event_type"] == "policy_decision"
        and "cross_server_instruction_policy" in e["message"]
        for e in events
    )


async def test_rug_pull_emits_metadata_diff_event(client: AsyncClient) -> None:
    await _run(client, "remote-sleeper-rug-pull", "vulnerable", "p-rug")

    response = await client.get(
        "/demo/events?session_id=p-rug",
        headers={"Origin": "http://testserver"},
    )
    events = response.json()["events"]
    assert any(
        e["event_type"] == "metadata_diff"
        or "hash" in e["message"].lower()
        or "metadata" in e["message"].lower()
        or "drift" in e["message"].lower()
        for e in events
    )


async def test_cross_session_leak_emits_alert_event(client: AsyncClient) -> None:
    # The canonical cross-session scenario enrols the two subjects
    # internally and runs the observation in a single shot.
    await _run(
        client,
        "remote-cross-session-context-leak",
        "vulnerable",
        "p-x-b",
    )

    response = await client.get(
        "/demo/events?session_id=p-x-b",
        headers={"Origin": "http://testserver"},
    )
    events = response.json()["events"]
    assert any(e["severity"] in {"warning", "error"} for e in events)
    assert any(
        "session_leak" in e["event_type"]
        or "cross_session" in e["message"].lower()
        or "session" in e["event_type"]
        for e in events
    )
