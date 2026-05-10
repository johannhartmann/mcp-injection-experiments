"""HTML UI smoke tests for the demo dashboard."""

from __future__ import annotations

from httpx import AsyncClient

import pytest





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


async def test_demo_run_accepts_form_post_from_dashboard_button(
    client: AsyncClient,
) -> None:
    """The /demo cards render <form method=post> with mode=<value>;
    browsers POST application/x-www-form-urlencoded. The route must
    accept that body shape (programmatic JSON callers also still
    work, see the test above). When the request comes from a browser
    (Accept: text/html), the response is a 303 redirect to the
    compare view; programmatic clients get JSON."""

    # Browser-style: form body + Accept: text/html -> 303 to /compare/...
    response = await client.post(
        "/demo/scenario/remote-direct-poisoning",
        headers={
            "Origin": "http://testserver",
            "Accept": "text/html",
        },
        data={"mode": "vulnerable"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == (
        "/demo/compare/remote-direct-poisoning"
    )

    # Programmatic-style: form body but Accept: application/json -> JSON.
    response = await client.post(
        "/demo/scenario/remote-direct-poisoning",
        headers={
            "Origin": "http://testserver",
            "Accept": "application/json",
        },
        data={"mode": "defended", "session_id": "form-sess"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "defended"
    assert body["experiment"] == "remote-direct-poisoning"
