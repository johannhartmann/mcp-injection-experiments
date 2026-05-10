"""Guardrails for public deployments."""

from __future__ import annotations

from httpx import AsyncClient
from mcp_demo.app import create_app

import pytest

from mcp_demo.config import DemoSettings




async def test_reset_endpoint_requires_admin_token(client: AsyncClient) -> None:
    response = await client.post(
        "/demo/reset",
        headers={"Origin": "http://testserver"},
        json={"session_id": "x"},
    )
    assert response.status_code == 401


async def test_reset_endpoint_rejects_wrong_admin_token(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/demo/reset",
        headers={
            "Origin": "http://testserver",
            "X-Demo-Admin-Token": "definitely-not-the-token",
        },
        json={"session_id": "x"},
    )
    assert response.status_code == 401


async def test_internal_errors_do_not_leak_tracebacks(
    client: AsyncClient,
) -> None:
    """An unhandled exception inside an endpoint must surface as a generic 5xx."""

    response = await client.post(
        "/demo/scenario/does-not-exist-anywhere",
        headers={"Origin": "http://testserver"},
        json={"mode": "vulnerable", "session_id": "x"},
    )
    # Unknown experiment is a 404, never a 500 with stacktrace.
    assert response.status_code == 404
    body = response.text
    assert "Traceback" not in body
    assert "Error\n  File " not in body


def test_public_mode_refuses_default_admin_token() -> None:
    """create_app refuses to start in public mode with the dev admin token."""

    settings = DemoSettings(
        admin_token="local-dev",
        allowed_origins=("https://demo.example.com",),
    )
    with pytest.raises(ValueError):
        create_app(settings=settings.with_public_mode())  # type: ignore[attr-defined]


def test_public_mode_refuses_wildcard_origin() -> None:
    settings = DemoSettings(
        admin_token="prod-secret-please-change",
        allowed_origins=("*",),
    )
    with pytest.raises(ValueError):
        create_app(settings=settings.with_public_mode())  # type: ignore[attr-defined]


def test_public_mode_accepts_safe_settings() -> None:
    settings = DemoSettings(
        admin_token="prod-secret-please-change",
        allowed_origins=("https://demo.example.com",),
    )
    app = create_app(settings=settings.with_public_mode())  # type: ignore[attr-defined]
    assert app is not None
