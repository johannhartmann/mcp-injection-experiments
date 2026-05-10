"""Liveness and readiness probe tests."""

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


async def test_healthz_does_not_require_origin(client: AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


async def test_readyz_reports_registered_experiments(client: AsyncClient) -> None:
    response = await client.get("/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["experiment_count"] >= 1
    assert "remote-direct-poisoning" in body["experiments"]


async def test_readyz_lists_all_experiments_present_in_registry(
    client: AsyncClient,
) -> None:
    response = await client.get("/readyz")
    body = response.json()
    # Sanity: every registered experiment id is unique and kebab-cased.
    ids = body["experiments"]
    assert len(ids) == len(set(ids))
    assert all(id_ == id_.lower() for id_ in ids)
