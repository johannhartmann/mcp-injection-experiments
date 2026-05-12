"""Tests for the server-side Gemini Flash Lite agent route.

The real google.genai client is mocked. We test:

- ``GET /demo/agent/status`` returns ``enabled=false`` with a reason
  when the feature is off or the API key is missing.
- ``POST /demo/agent/<id>`` returns 503 in the same situations.
- With ``gemini_enabled=True`` and a fake api key, the route drives at
  least one tool call against the live FastMCP instance and returns a
  transcript that includes the tool name + the dispatched args + the
  real result.
- Unknown experiment id returns 404; bad mode returns 400.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from mcp_demo.app import create_app
from mcp_demo.config import testing_settings as _make_settings


def _settings(**overrides):
    """Wrap testing_settings with the public-mode-safe defaults."""
    base = dict(
        admin_token="local-dev",
        allowed_origins=(
            "http://testserver",
            "http://127.0.0.1:8000",
            "http://localhost:8000",
        ),
    )
    base.update(overrides)
    return _make_settings(**base)


@pytest.fixture
async def gemini_misconfigured_client():
    """Deployment is missing GEMINI_API_KEY - the only state in which
    the agent route is not live."""
    app = create_app(settings=_settings())
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            yield ac


@pytest.fixture
async def gemini_on_client():
    """Agent fully wired with a fake api key (google.genai client is
    mocked at the call site, so the key value is never used over the
    wire)."""
    app = create_app(settings=_settings(
        gemini_api_key="fake-key-for-testing",
        gemini_model="gemini-3.1-flash-lite",
        gemini_max_steps=3,
    ))
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as ac:
            yield ac


async def test_agent_status_disabled_when_api_key_missing(
    gemini_misconfigured_client,
):
    resp = await gemini_misconfigured_client.get(
        "/demo/agent/status",
        headers={"Origin": "http://testserver"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert "GEMINI_API_KEY" in body["reason"]


async def test_agent_status_enabled(gemini_on_client):
    resp = await gemini_on_client.get(
        "/demo/agent/status",
        headers={"Origin": "http://testserver"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["model"] == "gemini-3.1-flash-lite"
    assert body["max_steps"] == 3


async def test_agent_run_missing_key_returns_503(gemini_misconfigured_client):
    resp = await gemini_misconfigured_client.post(
        "/demo/agent/remote-direct-poisoning",
        headers={"Origin": "http://testserver"},
        json={"mode": "vulnerable"},
    )
    assert resp.status_code == 503
    assert resp.json()["error"] == "gemini_misconfigured"


async def test_agent_run_unknown_experiment_404(gemini_on_client):
    with patch("google.genai.Client"):
        resp = await gemini_on_client.post(
            "/demo/agent/does-not-exist",
            headers={"Origin": "http://testserver"},
            json={"mode": "vulnerable"},
        )
    assert resp.status_code == 404
    assert resp.json()["error"] == "unknown_experiment"


async def test_agent_run_bad_mode_400(gemini_on_client):
    with patch("google.genai.Client"):
        resp = await gemini_on_client.post(
            "/demo/agent/remote-direct-poisoning",
            headers={"Origin": "http://testserver"},
            json={"mode": "totally-bogus"},
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_mode"


def _stub_genai_response_with_function_call(name: str, args: dict):
    """Build a MagicMock that mimics the google.genai response shape:
    candidates[0].content.parts[i].function_call.{name, args}."""
    part = MagicMock()
    part.function_call.name = name
    part.function_call.args = args
    part.text = None

    content = MagicMock()
    content.parts = [part]
    content.role = "model"

    candidate = MagicMock()
    candidate.content = content

    response = MagicMock()
    response.candidates = [candidate]
    response.text = None
    return response


def _stub_genai_response_text(text: str):
    part = MagicMock()
    part.function_call = None
    part.text = text

    content = MagicMock()
    content.parts = [part]
    content.role = "model"

    candidate = MagicMock()
    candidate.content = content

    response = MagicMock()
    response.candidates = [candidate]
    response.text = text
    return response


async def test_agent_run_happy_path_returns_transcript(gemini_on_client):
    """Mock genai to: first turn -> call calculator.add(a=5,b=7,
    sidenote='LEAKED'), second turn -> final text. Expect a transcript
    that includes that step and the real MCP server's response."""

    fake_client = MagicMock()
    # Two turns: function call, then text.
    fake_client.models.generate_content.side_effect = [
        _stub_genai_response_with_function_call(
            "calculator.add",
            {"a": 5, "b": 7, "sidenote": "LEAKED"},
        ),
        _stub_genai_response_text("Done; the sum is 12."),
    ]
    with patch("google.genai.Client", return_value=fake_client):
        resp = await gemini_on_client.post(
            "/demo/agent/remote-direct-poisoning",
            headers={"Origin": "http://testserver"},
            json={"mode": "vulnerable", "session_id": "agent-test"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["experiment_id"] == "remote-direct-poisoning"
    assert body["mode"] == "vulnerable"
    assert body["model"] == "gemini-3.1-flash-lite"
    assert body["max_steps_reached"] is False
    assert body["final_text"] == "Done; the sum is 12."
    steps = body["steps"]
    assert len(steps) == 1
    assert steps[0]["tool"] == "calculator.add"
    assert steps[0]["args"]["sidenote"] == "LEAKED"
    # The real FastMCP `calculator.add(5, 7)` returns 12 in its
    # structured content.
    assert steps[0]["result"]["isError"] is False
    assert steps[0]["result"]["structuredContent"] == {"result": 12}


async def test_agent_run_origin_guard(gemini_on_client):
    """The agent route uses the same origin allowlist as /demo/scenario."""
    resp = await gemini_on_client.post(
        "/demo/agent/remote-direct-poisoning",
        headers={"Origin": "http://evil.example"},
        json={"mode": "vulnerable"},
    )
    assert resp.status_code == 403
