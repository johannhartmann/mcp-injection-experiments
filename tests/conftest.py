"""Shared pytest fixtures.

The ``client`` fixture wraps :func:`mcp_demo.app.create_app` in an
``asgi_lifespan.LifespanManager`` so the FastAPI lifespan (and therefore
each mounted FastMCP server's session-manager task group) actually
runs while ``httpx.AsyncClient`` issues requests against the ASGI app.
"""

from __future__ import annotations

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from mcp_demo.app import create_app


@pytest.fixture
async def client():
    app = create_app()
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            yield ac
