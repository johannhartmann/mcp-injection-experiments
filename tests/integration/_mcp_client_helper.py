"""Shared helper for end-to-end Streamable-HTTP MCP tests.

Wraps the official ``mcp.client.streamable_http.streamable_http_client``
plus an in-process ``httpx.AsyncClient`` that talks to the FastAPI
ASGI app. No real socket, no real DNS, no real subprocess - the tests
exercise the same code path the production server runs.
"""

from __future__ import annotations

import contextlib

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


@contextlib.asynccontextmanager
async def mcp_session(app, mount_path: str):
    """Yield a connected :class:`ClientSession` for the given mount.

    ``mount_path`` is e.g. ``/mcp/direct-poisoning/vulnerable/``.
    """

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        headers={"Origin": "http://testserver"},
        timeout=30.0,
        follow_redirects=True,
    ) as http_client:
        async with streamable_http_client(
            url=f"http://testserver{mount_path}",
            http_client=http_client,
        ) as (read, write, _get_session_id):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
